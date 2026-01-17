import hashlib
import hmac
import json
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response

from app.logging import logger
from app.settings import settings

router = APIRouter()

# verify forgejo webhook signature
async def verify_forgejo_signature(request: Request) -> bytes:
    """
    Dependency to verify Forgejo webhook signatures (X-Hub-Signature-256)
    Verify HMAC-SHA256 signature from request header.
    Returns the raw request body if valid.
    Raises HTTPException if signature is missing or invalid.
    """
    payload = await request.body()
    signature = request.headers.get("X-Hub-Signature-256", "")

    if not signature:
        raise HTTPException(status_code=401, detail="Missing signature")

    if settings.forgejo_webhook_secret:
        expected = hmac.new(settings.forgejo_webhook_secret.encode(), payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(f"sha256={expected}", signature):
            raise HTTPException(status_code=401, detail="Invalid signature")

    return payload


# background task to process issue creation webhook
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
    # Placeholder for Modal sandbox invocation


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

