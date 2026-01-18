"""
Forgejo/Gitea API client for interacting with pull requests, issues, and comments.

This module provides typed functions for common Forgejo API operations needed
by the Photon bot to gather context and post updates during PR iteration.
"""

from typing import Any

import httpx

from app.logging import logger
from app.settings import settings


def _get_auth_headers() -> dict[str, str]:
    """Get authorization headers for Forgejo API requests."""
    return {
        "Authorization": f"token {settings.forgejo_api_token}",
        "Content-Type": "application/json",
    }


def _ensure_https(url: str) -> str:
    """Ensure URL uses HTTPS scheme."""
    return url.replace("http://", "https://")


async def get_pr_comments(repo_api_url: str, pr_number: int) -> list[dict[str, Any]]:
    """
    Fetch all comments on a pull request (issue-level comments).

    These are general discussion comments, not line-specific review comments.
    PR comments use the issues endpoint since PRs are a type of issue in Gitea/Forgejo.

    Args:
        repo_api_url: Base API URL for the repo (e.g., https://forgejo.example.com/api/v1/repos/owner/repo)
        pr_number: The pull request number (index)

    Returns:
        List of comment objects with 'user', 'body', 'created_at' fields
    """
    url = _ensure_https(f"{repo_api_url}/issues/{pr_number}/comments")

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=_get_auth_headers(), timeout=30)

            if response.status_code == 200:
                comments = response.json()
                logger.info(f"Fetched {len(comments)} PR comments for PR #{pr_number}")
                return comments
            else:
                logger.error(
                    f"Failed to fetch PR comments: {response.status_code} - {response.text}"
                )
                return []
    except Exception as e:
        logger.error(f"Error fetching PR comments: {e}")
        return []


async def get_pr_reviews(repo_api_url: str, pr_number: int) -> list[dict[str, Any]]:
    """
    Fetch all reviews on a pull request.

    Reviews contain the overall review state (approved, changes_requested, comment)
    and may have associated line-specific comments.

    Args:
        repo_api_url: Base API URL for the repo
        pr_number: The pull request number

    Returns:
        List of review objects with 'user', 'state', 'body', 'comments_count' fields
    """
    url = _ensure_https(f"{repo_api_url}/pulls/{pr_number}/reviews")

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=_get_auth_headers(), timeout=30)

            if response.status_code == 200:
                reviews = response.json()
                logger.info(f"Fetched {len(reviews)} reviews for PR #{pr_number}")
                return reviews
            else:
                logger.error(
                    f"Failed to fetch PR reviews: {response.status_code} - {response.text}"
                )
                return []
    except Exception as e:
        logger.error(f"Error fetching PR reviews: {e}")
        return []


async def get_review_comments(
    repo_api_url: str, pr_number: int, review_id: int
) -> list[dict[str, Any]]:
    """
    Fetch line-specific comments for a particular review.

    These comments are attached to specific lines in the diff and provide
    contextual feedback on particular code changes.

    Args:
        repo_api_url: Base API URL for the repo
        pr_number: The pull request number
        review_id: The review ID to fetch comments for

    Returns:
        List of review comment objects with 'path', 'line', 'body' fields
    """
    url = _ensure_https(f"{repo_api_url}/pulls/{pr_number}/reviews/{review_id}/comments")

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=_get_auth_headers(), timeout=30)

            if response.status_code == 200:
                comments = response.json()
                logger.info(f"Fetched {len(comments)} review comments for review #{review_id}")
                return comments
            else:
                logger.error(
                    f"Failed to fetch review comments: {response.status_code} - {response.text}"
                )
                return []
    except Exception as e:
        logger.error(f"Error fetching review comments: {e}")
        return []


async def get_all_review_comments(repo_api_url: str, pr_number: int) -> list[dict[str, Any]]:
    """
    Fetch all line-specific review comments across all reviews on a PR.

    This aggregates comments from all reviews, including file path and line context.

    Args:
        repo_api_url: Base API URL for the repo
        pr_number: The pull request number

    Returns:
        List of all review comments with review context attached
    """
    reviews = await get_pr_reviews(repo_api_url, pr_number)
    all_comments = []

    for review in reviews:
        review_id = review.get("id")
        if review_id and review.get("comments_count", 0) > 0:
            comments = await get_review_comments(repo_api_url, pr_number, review_id)
            # Attach review metadata to each comment for context
            for comment in comments:
                comment["_review_user"] = review.get("user", {}).get("login", "unknown")
                comment["_review_state"] = review.get("state", "unknown")
            all_comments.extend(comments)

    logger.info(f"Fetched {len(all_comments)} total review comments for PR #{pr_number}")
    return all_comments


async def get_issue_details(repo_api_url: str, issue_number: int) -> dict[str, Any] | None:
    """
    Fetch details of an issue.

    Args:
        repo_api_url: Base API URL for the repo
        issue_number: The issue number

    Returns:
        Issue object with 'title', 'body', 'user', 'state' fields, or None if not found
    """
    url = _ensure_https(f"{repo_api_url}/issues/{issue_number}")

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=_get_auth_headers(), timeout=30)

            if response.status_code == 200:
                issue = response.json()
                logger.info(f"Fetched issue #{issue_number}: {issue.get('title', 'untitled')}")
                return issue
            else:
                logger.warning(f"Issue #{issue_number} not found: {response.status_code}")
                return None
    except Exception as e:
        logger.error(f"Error fetching issue details: {e}")
        return None


async def get_issue_comments(repo_api_url: str, issue_number: int) -> list[dict[str, Any]]:
    """
    Fetch all comments on an issue.

    Args:
        repo_api_url: Base API URL for the repo
        issue_number: The issue number

    Returns:
        List of comment objects with 'user', 'body', 'created_at' fields
    """
    url = _ensure_https(f"{repo_api_url}/issues/{issue_number}/comments")

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=_get_auth_headers(), timeout=30)

            if response.status_code == 200:
                comments = response.json()
                logger.info(f"Fetched {len(comments)} comments for issue #{issue_number}")
                return comments
            else:
                logger.error(
                    f"Failed to fetch issue comments: {response.status_code} - {response.text}"
                )
                return []
    except Exception as e:
        logger.error(f"Error fetching issue comments: {e}")
        return []


async def post_pr_comment(repo_api_url: str, pr_number: int, body: str) -> bool:
    """
    Post a comment on a pull request.

    Used to provide status updates like "Photon is working on changes..."

    Args:
        repo_api_url: Base API URL for the repo
        pr_number: The pull request number
        body: The comment text (supports markdown)

    Returns:
        True if comment was posted successfully, False otherwise
    """
    url = _ensure_https(f"{repo_api_url}/issues/{pr_number}/comments")
    payload = {"body": body}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(url, json=payload, headers=_get_auth_headers(), timeout=30)

            if response.status_code == 201:
                logger.info(f"Posted comment on PR #{pr_number}")
                return True
            else:
                logger.error(f"Failed to post comment: {response.status_code} - {response.text}")
                return False
    except Exception as e:
        logger.error(f"Error posting PR comment: {e}")
        return False


async def get_pr_diff(repo_api_url: str, pr_number: int) -> str | None:
    """
    Fetch the diff for a pull request.

    Args:
        repo_api_url: Base API URL for the repo
        pr_number: The pull request number

    Returns:
        The diff as a string, or None if fetch failed
    """
    # Construct diff URL from repo API URL
    # repo_api_url: https://forgejo.example.com/api/v1/repos/owner/repo
    # diff_url: https://forgejo.example.com/owner/repo/pulls/{pr_number}.diff
    base_url = repo_api_url.replace("/api/v1/repos/", "/")
    url = _ensure_https(f"{base_url}/pulls/{pr_number}.diff")

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=_get_auth_headers(), timeout=60)

            if response.status_code == 200:
                diff = response.text
                logger.info(f"Fetched diff for PR #{pr_number} ({len(diff)} chars)")
                return diff
            else:
                logger.error(f"Failed to fetch PR diff: {response.status_code}")
                return None
    except Exception as e:
        logger.error(f"Error fetching PR diff: {e}")
        return None
