"""One pull request comment per PR, updated in place on every push."""

from __future__ import annotations

from typing import Any

from newsoc_code.github.client import GitHubClient, GitHubError
from newsoc_code.report.render import COMMENT_MARKER


def _ours(comment: dict[str, Any], app_id: int) -> bool:
    """Our marker AND created by our app: a user pasting the marker cannot hijack the update."""
    via = comment.get("performed_via_github_app") or {}
    return COMMENT_MARKER in (comment.get("body") or "") and via.get("id") == app_id


def upsert_summary_comment(
    client: GitHubClient,
    installation_id: int,
    repo: str,
    number: int,
    body: str,
    known_comment_id: int | None = None,
) -> int:
    """Update our comment if it exists (by remembered id, else by search), otherwise create it."""
    if known_comment_id is not None:
        try:
            client.update_comment(installation_id, repo, known_comment_id, body)
            return known_comment_id
        except GitHubError as exc:
            if exc.status not in (403, 404):  # deleted by someone: fall through and look again
                raise
    for comment in client.list_comments(installation_id, repo, number):
        if _ours(comment, client.app_id):
            client.update_comment(installation_id, repo, int(comment["id"]), body)
            return int(comment["id"])
    return client.create_comment(installation_id, repo, number, body)
