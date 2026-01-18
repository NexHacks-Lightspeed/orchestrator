import hashlib
import hmac
import json
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx
import modal
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response

from app.logging import logger
from app.settings import settings

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
    """Build Modal image with git, node, bun, opencode-ai, and opencode-lens installed."""
    repo_root = Path(__file__).parent.parent
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
        .add_local_file(f"{repo_root}/opencode-lens", "/usr/local/bin/opencode-lens", copy=True)
        .run_commands("chmod +x /usr/local/bin/opencode-lens")
        .run_commands("mkdir -p /root/.config/opencode")
        .add_local_file(
            f"{repo_root}/opencode-sandbox.json", "/root/.config/opencode/opencode.json", copy=True
        )
    )


def _get_sandbox_env() -> dict[str, str | None]:
    """Get environment variables for the sandbox."""
    return {
        "OPENCODE_LOG_LEVEL": "info",
        "OPENCODE_LENS_PROXY_URL": settings.litellm_proxy_url,
    }


@contextmanager
def _sandbox_context(timeout: int = 600):
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
    """Setup OpenCode and OpenCode Lens in the sandbox."""
    logger.info("Setting up OpenCode configuration")

    # Verify opencode-lens is executable
    if not _exec_or_fail(sandbox, "/usr/local/bin/opencode-lens", "--help", timeout=15):
        logger.error("OpenCode Lens verification failed")
        return False

    logger.info("OpenCode Lens is ready")

    # Verify opencode is installed
    if not _exec_or_fail(sandbox, "opencode", "--version", timeout=15):
        logger.error("OpenCode verification failed")
        return False

    logger.info("OpenCode configuration complete")
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
    cmd = f"cd /repo && opencode-lens run --print-logs --log-level DEBUG '{escaped_prompt}'"
    p = sandbox.exec("bash", "-c", cmd, timeout=300)
    p.wait()

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
    if not _exec_or_fail(sandbox, "git", "clone", "--depth", "1", repo_url, "repo", timeout=60):
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
