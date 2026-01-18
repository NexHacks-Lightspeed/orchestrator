import hashlib
import hmac
import json
import re
from contextlib import contextmanager
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx
import modal
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response

from app.forgejo_client import (
    get_all_review_comments,
    get_issue_comments,
    get_issue_details,
    get_pr_comments,
    get_pr_reviews,
    post_pr_comment,
)
from app.logging import logger
from app.settings import settings

# Constants
PHOTON_BOT_USERNAME = "Photon"
SANDBOX_TIMEOUT_SECONDS = 600  # 10 minutes

router = APIRouter()


async def verify_forgejo_signature(request: Request) -> bytes:
    """
    Dependency to verify Forgejo webhook signatures (X-Hub-Signature-256)
    Verify HMAC-SHA256 signature from request header.
    Returns the raw request body if valid.
    Raises HTTPException if signature is missing or invalid.
    """
    logger.info(f"Received {request.method} request to {request.url.path}")
    logger.debug(f"Headers: {dict(request.headers)}")

    payload = await request.body()
    signature = request.headers.get("X-Hub-Signature-256", "")

    logger.debug(
        f"Webhook signature header: {signature[:20]}..."
        if len(signature) > 20
        else f"Webhook signature header: {signature}"
    )
    logger.debug(f"Webhook secret configured: {bool(settings.forgejo_webhook_secret)}")

    if not signature:
        raise HTTPException(status_code=401, detail="Missing signature")

    if settings.forgejo_webhook_secret:
        expected = hmac.new(
            settings.forgejo_webhook_secret.encode(), payload, hashlib.sha256
        ).hexdigest()
        logger.debug(
            f"Computed expected: sha256={expected[:20]}..."
            if len(expected) > 20
            else f"Computed expected: sha256={expected}"
        )
        if not hmac.compare_digest(f"sha256={expected}", signature):
            raise HTTPException(status_code=401, detail="Invalid signature")

    return payload


def _exec_or_fail(sandbox: modal.Sandbox, *args: str, timeout: int = 30) -> bool:
    """
    Execute a command in the sandbox.
    Returns True on success, False on failure (logs the error).
    """
    p = sandbox.exec(*args, timeout=timeout)
    p.wait()
    if p.returncode != 0:
        cmd_str = " ".join(args[:3]) + ("..." if len(args) > 3 else "")
        logger.error(f"Command failed [{cmd_str}]: {p.stderr.read()}")
        return False
    return True


def _build_opencode_image() -> modal.Image:
    """Build Modal image with git, node, bun, and opencode-ai installed."""
    return (
        modal.Image.debian_slim()
        .apt_install("git", "curl", "ca-certificates", "sudo", "build-essential", "unzip")
        .run_commands("curl -fsSL https://deb.nodesource.com/setup_20.x | bash -")
        .apt_install("nodejs")
        .run_commands("curl -fsSL https://bun.sh/install | bash")
        .env(
            {"PATH": "/root/.bun/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
        )
        .run_commands("bun install -g opencode-ai")
    )


def _get_sandbox_env() -> dict[str, str | None]:
    """Get environment variables for the sandbox."""
    return {
        "OPENCODE_PROVIDER": settings.opencode_provider,
        "OPENCODE_MODEL": settings.opencode_model,
        "OPENCODE_LOG_LEVEL": "info",
    }


@contextmanager
def _sandbox_context(timeout: int = SANDBOX_TIMEOUT_SECONDS):
    """Context manager for Modal sandbox lifecycle."""
    app = modal.App.lookup(settings.modal_app_name, create_if_missing=True)
    sb = modal.Sandbox.create(
        app=app,
        image=_build_opencode_image(),
        timeout=timeout,
        env=_get_sandbox_env(),
        cpu=2.0,
        memory=1024,
    )
    try:
        yield sb
    finally:
        sb.terminate()
        logger.info("Sandbox terminated")


def _setup_opencode(sandbox: modal.Sandbox) -> bool:
    """Setup OpenCode authentication and configuration in the sandbox."""
    logger.info("Setting up OpenCode authentication")

    if settings.opencode_zen_api_key:
        setup_cmd = f"echo {settings.opencode_zen_api_key} | opencode connect zen"
        if not _exec_or_fail(sandbox, "bash", "-c", setup_cmd, timeout=30):
            logger.error("OpenCode Zen authentication failed")
            return False
        logger.info("OpenCode Zen authentication successful")
    else:
        logger.warning("No OpenCode Zen API key provided, using unauthenticated mode")

    if not _exec_or_fail(sandbox, "opencode", "--version", timeout=15):
        logger.error("OpenCode verification failed")
        return False

    return True


def _run_opencode(sandbox: modal.Sandbox, issue_data: dict) -> str | None:
    """Run OpenCode to analyze and fix the issue."""
    issue_number = issue_data.get("number", 0)
    issue_title = issue_data.get("title", "")
    issue_body = issue_data.get("body", "")

    prompt = f"""You are fixing a GitHub issue in this repository.

Issue #{issue_number}: {issue_title}

{issue_body}

Instructions:
1. First, analyze the issue and write your analysis and implementation plan to .photon/analysis.md
2. Then implement the fix by editing the necessary files
3. Do NOT delete .photon/analysis.md - it will be used for the PR description

Focus on making minimal, targeted changes that directly address the issue."""

    logger.info(f"Running OpenCode for issue #{issue_number}")

    escaped_prompt = prompt.replace("'", "'\\''")
    cmd = (
        f"cd /repo && script -q -c "
        f"\"opencode run --print-logs --log-level DEBUG '{escaped_prompt}'\" "
        f"/tmp/opencode.log"
    )
    p = sandbox.exec("bash", "-c", cmd, timeout=300)
    p.wait()

    log_proc = sandbox.exec("cat", "/tmp/opencode.log", timeout=10)
    log_proc.wait()
    log_output = log_proc.stdout.read()
    if log_output:
        logger.info(f"[OpenCode output] {log_output[:5000]}")

    if p.returncode != 0:
        logger.error(f"OpenCode failed with exit code {p.returncode}")
        return None

    logger.info("OpenCode completed successfully")

    p = sandbox.exec("cat", "/repo/.photon/analysis.md", timeout=10)
    p.wait()

    if p.returncode != 0:
        logger.info("No analysis scratchpad found, using default PR description")
        return ""

    return p.stdout.read()


def _create_pull_request(
    repo_api_url: str,
    issue_number: int,
    branch_name: str,
    issue_data: dict,
    analysis: str | None = None,
) -> bool:
    """Create a pull request via Forgejo API."""
    pr_url = f"{repo_api_url}/pulls".replace("http://", "https://")
    headers = {
        "Authorization": f"token {settings.forgejo_api_token}",
        "Content-Type": "application/json",
    }

    issue_title = issue_data.get("title", "")
    issue_body = issue_data.get("body", "")

    if analysis:
        pr_description = (
            f"## Automated PR for issue #{issue_number}\n\n"
            f"**Original Issue:** {issue_title}\n\n"
            f"**Issue Description:**\n{issue_body}\n\n"
            f"**OpenCode Analysis:**\n```\n{analysis}\n```\n\n"
            f"This pull request was automatically generated by Photon using OpenCode AI."
        )
    else:
        pr_description = f"Automated PR for issue #{issue_number}"

    payload = {
        "title": f"Photon: Fix issue #{issue_number}",
        "head": branch_name,
        "base": "main",
        "body": pr_description,
    }

    try:
        response = httpx.post(pr_url, json=payload, headers=headers, timeout=30)
        if response.status_code in (201, 422):
            logger.info(f"PR created or already exists for issue #{issue_number}")
            return True
        logger.error(f"Failed to create PR: {response.status_code} - {response.text}")
        return False
    except Exception as e:
        logger.error(f"PR creation error: {e}")
        return False


def _run_git_workflow(
    sandbox: modal.Sandbox,
    repo_url: str,
    issue_number: int,
    repo_api_url: str,
    issue_data: dict,
) -> None:
    """Run the git workflow: clone, branch, run OpenCode, commit, push, and create PR."""
    branch_name = f"photon/issue_{issue_number}"

    logger.info(f"Cloning repository: {repo_url}")
    # Clone full history to provide git log context for the agent
    if not _exec_or_fail(sandbox, "git", "clone", repo_url, "repo", timeout=120):
        logger.error("Git clone failed, aborting workflow")
        return

    logger.info(f"Creating branch: {branch_name}")
    if not _exec_or_fail(
        sandbox, "bash", "-c", f"cd repo && git checkout -b {branch_name}", timeout=10
    ):
        logger.error("Git branch creation failed, aborting workflow")
        return

    if not _setup_opencode(sandbox):
        logger.error("OpenCode setup failed, aborting workflow")
        return

    analysis = _run_opencode(sandbox, issue_data)
    if analysis is None:
        logger.error("OpenCode execution failed, aborting workflow")
        return

    logger.info("Staging changes")
    stage_cmd = "cd repo && git add -A && git reset .photon/ 2>/dev/null || true"
    if not _exec_or_fail(sandbox, "bash", "-c", stage_cmd, timeout=10):
        logger.error("Git staging failed, aborting workflow")
        return

    check_cmd = "cd repo && git diff --cached --quiet"
    p = sandbox.exec("bash", "-c", check_cmd, timeout=10)
    p.wait()
    if p.returncode == 0:
        logger.warning("No changes to commit, aborting workflow")
        return

    logger.info("Committing changes")
    commit_message = f"Resolve issue #{issue_number}: {issue_data.get('title', 'Automated fix')}"
    commit_cmd = (
        f"cd repo && git config user.email 'photon@lightspeed' && "
        f"git config user.name 'Photon' && "
        f"git commit -m '{commit_message}'"
    )
    if not _exec_or_fail(sandbox, "bash", "-c", commit_cmd, timeout=10):
        logger.error("Git commit failed, aborting workflow")
        return

    logger.info("Pushing branch")
    parsed = urlparse(repo_url)
    auth_url = urlunparse(
        parsed._replace(
            scheme="https",
            netloc=f"x-token:{settings.forgejo_api_token}@{parsed.netloc}",
        )
    )
    push_cmd = f"cd repo && git push {auth_url} {branch_name}"
    if not _exec_or_fail(sandbox, "bash", "-c", push_cmd, timeout=30):
        logger.error("Git push failed, aborting workflow")
        return

    logger.info("Creating pull request")
    if _create_pull_request(repo_api_url, issue_number, branch_name, issue_data, analysis):
        logger.info("Git workflow completed successfully")
    else:
        logger.error("Git workflow failed at PR creation")


async def process_issue_background(data: dict[str, Any]) -> None:
    """
    Background task handler for processing incoming issue webhooks.
    Spawns a Modal sandbox to analyze the issue with OpenCode and implement solutions.
    """
    issue = data.get("issue", {})
    repo = data.get("repository", {})

    logger.info(
        f"Processing issue webhook - "
        f"repo: {repo.get('full_name', 'unknown')}, "
        f"issue: #{issue.get('number', 'unknown')}, "
        f"title: {issue.get('title', 'unknown')}"
    )

    clone_url = repo.get("clone_url")
    repo_api_url = repo.get("url")
    if not clone_url or not repo_api_url:
        logger.error("No clone_url or repo_api_url found in repository data")
        return

    logger.info(f"Spawning Modal sandbox with OpenCode for {clone_url}")

    try:
        with _sandbox_context(timeout=600) as sandbox:
            _run_git_workflow(
                sandbox,
                clone_url,
                issue.get("number", 0),
                repo_api_url,
                issue,
            )
    except Exception as e:
        logger.error(f"Sandbox execution failed: {e}")


# =============================================================================
# Review Iterate Endpoint - For iterating on PRs based on reviewer feedback
# =============================================================================


def _extract_issue_number(pr_body: str, branch_name: str) -> int | None:
    """
    Extract the linked issue number from PR body or branch name.

    Tries multiple patterns:
    1. "Automated PR for issue #X" in PR body
    2. "photon/issue_X" in branch name

    Args:
        pr_body: The pull request body/description
        branch_name: The PR head branch name

    Returns:
        Issue number if found, None otherwise
    """
    # Try PR body pattern: "Automated PR for issue #X" or "issue #X"
    body_match = re.search(r"issue\s*#(\d+)", pr_body, re.IGNORECASE)
    if body_match:
        return int(body_match.group(1))

    # Try branch name pattern: "photon/issue_X"
    branch_match = re.search(r"photon/issue_(\d+)", branch_name, re.IGNORECASE)
    if branch_match:
        return int(branch_match.group(1))

    return None


def _format_comments_for_prompt(comments: list[dict], label: str) -> str:
    """
    Format a list of comments into a readable string for the agent prompt.

    Args:
        comments: List of comment objects with 'user', 'body', 'created_at'
        label: Label to describe this section (e.g., "PR Comments")

    Returns:
        Formatted string with all comments
    """
    if not comments:
        return f"## {label}\nNo comments.\n"

    lines = [f"## {label}"]
    for comment in comments:
        user = comment.get("user", {}).get("login", "unknown")
        body = comment.get("body", "").strip()
        created = comment.get("created_at", "unknown time")
        lines.append(f"\n### @{user} ({created}):\n{body}")

    return "\n".join(lines)


def _format_reviews_for_prompt(reviews: list[dict]) -> str:
    """
    Format PR reviews into a readable string for the agent prompt.

    Args:
        reviews: List of review objects with 'user', 'state', 'body'

    Returns:
        Formatted string with all reviews
    """
    if not reviews:
        return "## PR Reviews\nNo reviews yet.\n"

    lines = ["## PR Reviews"]
    for review in reviews:
        user = review.get("user", {}).get("login", "unknown")
        state = review.get("state", "unknown")
        body = review.get("body", "").strip()
        lines.append(f"\n### @{user} - {state.upper()}:")
        if body:
            lines.append(body)

    return "\n".join(lines)


def _format_review_comments_for_prompt(comments: list[dict]) -> str:
    """
    Format line-specific review comments for the agent prompt.

    Args:
        comments: List of review comment objects with file/line context

    Returns:
        Formatted string with all review comments
    """
    if not comments:
        return "## Line-Specific Review Comments\nNo line comments.\n"

    lines = ["## Line-Specific Review Comments"]
    for comment in comments:
        user = comment.get("_review_user", comment.get("user", {}).get("login", "unknown"))
        path = comment.get("path", "unknown file")
        line = comment.get("line", comment.get("old_line", "?"))
        body = comment.get("body", "").strip()
        lines.append(f"\n### {path}:{line} (@{user}):")
        lines.append(body)

    return "\n".join(lines)


def _build_authenticated_remote_url(repo_url: str) -> str:
    """
    Build an authenticated git remote URL using the Forgejo API token.

    Args:
        repo_url: The original clone URL

    Returns:
        URL with embedded authentication token
    """
    parsed = urlparse(repo_url)
    return urlunparse(
        parsed._replace(
            scheme="https",
            netloc=f"x-token:{settings.forgejo_api_token}@{parsed.netloc}",
        )
    )


def _run_opencode_iterate(
    sandbox: modal.Sandbox,
    prompt: str,
    branch_name: str,
) -> bool:
    """
    Run OpenCode with a prompt for iterating on an existing PR.

    The prompt instructs the agent to make incremental commits as it works,
    providing liveness to reviewers watching the PR.

    Args:
        sandbox: The Modal sandbox instance
        prompt: The full context prompt for the agent
        branch_name: The PR branch name (for commit/push)

    Returns:
        True if OpenCode completed successfully, False otherwise
    """
    logger.info(f"Running OpenCode iteration for branch {branch_name}")

    escaped_prompt = prompt.replace("'", "'\\''")
    cmd = (
        f"cd /repo && script -q -c "
        f"\"opencode run --print-logs --log-level DEBUG '{escaped_prompt}'\" "
        f"/tmp/opencode.log"
    )
    p = sandbox.exec("bash", "-c", cmd, timeout=SANDBOX_TIMEOUT_SECONDS - 60)
    p.wait()

    # Read and log output
    log_proc = sandbox.exec("cat", "/tmp/opencode.log", timeout=10)
    log_proc.wait()
    log_output = log_proc.stdout.read()
    if log_output:
        logger.info(f"[OpenCode iteration output] {log_output[:5000]}")

    if p.returncode != 0:
        logger.error(f"OpenCode iteration failed with exit code {p.returncode}")
        return False

    logger.info("OpenCode iteration completed successfully")
    return True


def _run_git_workflow_iterate(
    sandbox: modal.Sandbox,
    repo_url: str,
    branch_name: str,
    prompt: str,
) -> bool:
    """
    Run the git workflow for iterating on an existing PR branch.

    Unlike the initial workflow, this:
    - Clones full history for git log context
    - Checks out the existing branch (doesn't create new)
    - Configures git remote with push access for incremental commits
    - Agent is responsible for committing and pushing as it works

    Args:
        sandbox: The Modal sandbox instance
        repo_url: Repository clone URL
        branch_name: The existing PR branch to check out
        prompt: The full context prompt for the agent

    Returns:
        True if workflow completed successfully, False otherwise
    """
    logger.info(f"Starting git workflow iteration for branch: {branch_name}")

    # Clone full history for git log context
    logger.info(f"Cloning repository: {repo_url}")
    if not _exec_or_fail(sandbox, "git", "clone", repo_url, "repo", timeout=120):
        logger.error("Git clone failed, aborting iteration workflow")
        return False

    # Checkout existing branch
    logger.info(f"Checking out existing branch: {branch_name}")
    checkout_cmd = f"cd repo && git checkout {branch_name}"
    if not _exec_or_fail(sandbox, "bash", "-c", checkout_cmd, timeout=30):
        logger.error(f"Failed to checkout branch {branch_name}, aborting")
        return False

    # Configure git user for commits
    git_config_cmd = (
        "cd repo && git config user.email 'photon@lightspeed' && git config user.name 'Photon'"
    )
    if not _exec_or_fail(sandbox, "bash", "-c", git_config_cmd, timeout=10):
        logger.error("Git config failed, aborting")
        return False

    # Configure authenticated remote for push access
    auth_url = _build_authenticated_remote_url(repo_url)
    remote_cmd = f"cd repo && git remote set-url origin {auth_url}"
    if not _exec_or_fail(sandbox, "bash", "-c", remote_cmd, timeout=10):
        logger.error("Failed to configure authenticated remote, aborting")
        return False

    # Setup OpenCode
    if not _setup_opencode(sandbox):
        logger.error("OpenCode setup failed, aborting iteration workflow")
        return False

    # Run OpenCode with iteration prompt
    if not _run_opencode_iterate(sandbox, prompt, branch_name):
        logger.error("OpenCode iteration failed")
        return False

    logger.info("Git workflow iteration completed successfully")
    return True


async def _gather_review_context(
    repo_api_url: str,
    pr_number: int,
    pr_body: str,
    branch_name: str,
) -> dict[str, Any]:
    """
    Gather all context needed for iterating on a PR.

    Fetches from Forgejo API:
    - PR comments (general discussion)
    - PR reviews and their line-specific comments
    - Linked issue details and comments (if found)

    Args:
        repo_api_url: Base API URL for the repo
        pr_number: The pull request number
        pr_body: The PR body/description
        branch_name: The PR branch name

    Returns:
        Dict with all gathered context
    """
    context: dict[str, Any] = {
        "pr_comments": [],
        "pr_reviews": [],
        "review_comments": [],
        "issue_number": None,
        "issue_details": None,
        "issue_comments": [],
    }

    # Fetch PR-level context
    context["pr_comments"] = await get_pr_comments(repo_api_url, pr_number)
    context["pr_reviews"] = await get_pr_reviews(repo_api_url, pr_number)
    context["review_comments"] = await get_all_review_comments(repo_api_url, pr_number)

    # Try to find and fetch linked issue
    issue_number = _extract_issue_number(pr_body, branch_name)
    if issue_number:
        context["issue_number"] = issue_number
        context["issue_details"] = await get_issue_details(repo_api_url, issue_number)
        context["issue_comments"] = await get_issue_comments(repo_api_url, issue_number)
        logger.info(f"Found linked issue #{issue_number}")
    else:
        logger.info("No linked issue number found in PR body or branch name")

    return context


def _build_iteration_prompt(
    pr_data: dict,
    context: dict[str, Any],
    branch_name: str,
) -> str:
    """
    Build the full prompt for the OpenCode agent to iterate on a PR.

    Includes:
    - Original issue context (if available)
    - PR discussion and review feedback
    - Instructions for incremental commits

    Args:
        pr_data: The pull request data from the webhook
        context: Gathered context from Forgejo API
        branch_name: The PR branch name

    Returns:
        Complete prompt string for the agent
    """
    pr_title = pr_data.get("title", "")
    pr_body = pr_data.get("body", "")

    # Build issue context section
    issue_section = ""
    if context["issue_details"]:
        issue = context["issue_details"]
        issue_section = f"""
## Original Issue
Issue #{context["issue_number"]}: {issue.get("title", "")}

{issue.get("body", "")}

{_format_comments_for_prompt(context["issue_comments"], "Issue Discussion")}
"""
    else:
        issue_section = """
## Original Issue
No linked issue found. Please infer the original requirements from the PR description,
existing commits, and the git log history.
"""

    # Format PR feedback sections
    pr_comments_section = _format_comments_for_prompt(context["pr_comments"], "PR Discussion")
    reviews_section = _format_reviews_for_prompt(context["pr_reviews"])
    review_comments_section = _format_review_comments_for_prompt(context["review_comments"])

    prompt = f"""You are iterating on an existing pull request based on reviewer feedback.

## Current PR
Title: {pr_title}
Branch: {branch_name}

### PR Description
{pr_body}

{issue_section}

{pr_comments_section}

{reviews_section}

{review_comments_section}

## Instructions

You are addressing reviewer feedback on this pull request. Follow these guidelines:

1. **Read all feedback carefully** - Review comments, PR discussion, and line-specific comments
2. **Address each piece of feedback** - Make the requested changes or improvements
3. **Commit incrementally** - After each logical change, commit and push:
   ```bash
   git add -A
   git commit -m "type: short description" -m "Detailed explanation of the change and which feedback it addresses"
   git push origin {branch_name}
   ```
4. **Use descriptive commit messages**:
   - Short header (50 chars max): What was changed
   - Extended body: Why it was changed, referencing the specific feedback
5. **Update .photon/analysis.md** - Add notes on what you changed and why
6. **Do NOT squash commits** - Each change should be its own commit for reviewer visibility

### Commit Message Format
```
<type>: <short description>

<detailed explanation>
Addresses feedback from @<reviewer> regarding <topic>
```

Types: fix, feat, refactor, style, docs, test, chore

### Important
- You have push access configured - use `git push origin {branch_name}` directly
- Reviewers can see your commits in real-time as you push
- Focus on the specific feedback provided, don't make unrelated changes
- If feedback is unclear, make your best judgment and explain in the commit message

Begin by reviewing the feedback and planning your changes."""

    return prompt


async def process_review_background(data: dict[str, Any]) -> None:
    """
    Background task handler for processing PR review webhooks.

    Gathers context from Forgejo API, posts a status comment, then spawns
    a Modal sandbox to run OpenCode and iterate on the PR.
    """
    pr_data = data.get("pull_request", {})
    repo = data.get("repository", {})
    review = data.get("review", {})

    pr_number = pr_data.get("number", 0)
    pr_title = pr_data.get("title", "")
    pr_body = pr_data.get("body", "")
    branch_name = pr_data.get("head", {}).get("ref", "")

    logger.info(
        f"Processing review webhook - "
        f"repo: {repo.get('full_name', 'unknown')}, "
        f"PR: #{pr_number}, "
        f"review type: {review.get('type', 'unknown')}"
    )

    clone_url = repo.get("clone_url")
    repo_api_url = repo.get("url")
    if not clone_url or not repo_api_url:
        logger.error("No clone_url or repo_api_url found in repository data")
        return

    if not branch_name:
        logger.error("No branch name found in PR data")
        return

    # Post "working on it" comment
    await post_pr_comment(
        repo_api_url,
        pr_number,
        "**Photon** is working on the requested changes. "
        "Watch this PR for incremental commits as updates are made.",
    )

    # Gather all context from Forgejo API
    logger.info(f"Gathering context for PR #{pr_number}")
    context = await _gather_review_context(repo_api_url, pr_number, pr_body, branch_name)

    # Build the iteration prompt
    prompt = _build_iteration_prompt(pr_data, context, branch_name)

    logger.info(f"Spawning Modal sandbox for PR iteration on {clone_url}")

    try:
        with _sandbox_context(timeout=SANDBOX_TIMEOUT_SECONDS) as sandbox:
            success = _run_git_workflow_iterate(
                sandbox,
                clone_url,
                branch_name,
                prompt,
            )

            if success:
                await post_pr_comment(
                    repo_api_url,
                    pr_number,
                    "**Photon** has finished addressing the review feedback. "
                    "Please review the new commits.",
                )
            else:
                await post_pr_comment(
                    repo_api_url,
                    pr_number,
                    "**Photon** encountered an issue while processing the feedback. "
                    "Please check the logs or try again.",
                )
    except Exception as e:
        logger.error(f"Sandbox execution failed: {e}")
        await post_pr_comment(
            repo_api_url, pr_number, f"**Photon** encountered an error: {str(e)[:200]}"
        )


@router.post("/review-iterate")
async def handle_review_webhook(
    background_tasks: BackgroundTasks,
    payload: bytes = Depends(verify_forgejo_signature),
):
    """
    Handle incoming Forgejo PR review webhooks.

    Triggers iteration on a PR when:
    - Action is "reviewed"
    - Review type is "changes_requested" or "comment" (not "approved")
    - PR was created by Photon bot

    Returns 202 Accepted and processes in background.
    """
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {e}") from None

    action = data.get("action")
    if action != "reviewed":
        logger.info(f"Ignoring review webhook with action: {action}")
        return Response(status_code=200, content=b"Ignored: only 'reviewed' action supported")

    # Check review type - only respond to changes_requested or comment, not approved
    review = data.get("review", {})
    review_type = review.get("type", "")
    if review_type not in ("pull_request_review_rejected", "pull_request_review_comment"):
        logger.info(f"Ignoring review with type: {review_type}")
        return Response(
            status_code=200,
            content=b"Ignored: only changes_requested or comment reviews trigger iteration",
        )

    # Check if PR was created by Photon
    pr_data = data.get("pull_request", {})
    pr_author = pr_data.get("user", {}).get("login", "")
    if pr_author != PHOTON_BOT_USERNAME:
        logger.info(f"Ignoring review on PR by non-Photon author: {pr_author}")
        return Response(status_code=200, content=b"Ignored: only Photon-created PRs are processed")

    background_tasks.add_task(process_review_background, data)
    logger.info(f"Scheduled PR #{pr_data.get('number', 'unknown')} for review iteration")
    return Response(status_code=202, content=b"Accepted")


# =============================================================================
# Issue Endpoint - For creating new PRs from issues
# =============================================================================


@router.post("/issue")
async def handle_issue_webhook(
    background_tasks: BackgroundTasks,
    payload: bytes = Depends(verify_forgejo_signature),
):
    """Handle incoming Forgejo issue webhooks."""
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {e}") from None

    action = data.get("action")
    if action != "opened":
        return Response(status_code=200, content=b"Ignored: only 'opened' action supported")

    background_tasks.add_task(process_issue_background, data)
    logger.info("Scheduled issue for background processing")
    return Response(status_code=202, content=b"Accepted")
