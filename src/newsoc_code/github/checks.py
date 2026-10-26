"""Publishing a scan result as a GitHub check run."""

from __future__ import annotations

import logging

from newsoc_code.github.client import GitHubClient, GitHubError
from newsoc_code.policy.engine import Conclusion
from newsoc_code.report.render import CheckOutput, annotation_batches

log = logging.getLogger(__name__)


def publish_result(
    client: GitHubClient,
    installation_id: int,
    repo: str,
    check_run_id: int,
    output: CheckOutput,
    conclusion: Conclusion,
) -> None:
    """Send annotations 50 at a time, then complete the run with its conclusion.

    The conclusion goes with the last request so the check never completes before its
    annotations are in. If GitHub rejects the annotations (for example a path it cannot place),
    the check is still completed without them: a stuck required check is worse than a missing
    inline note.
    """
    batches = annotation_batches(output.annotations) or [[]]
    summary = output.summary
    if output.truncated_annotations:
        summary += f"\n\n{output.truncated_annotations} more finding(s) are not annotated inline."
    try:
        for batch in batches[:-1]:
            client.update_check_run(
                installation_id,
                repo,
                check_run_id,
                title=output.title,
                summary=summary,
                annotations=batch,
            )
        client.update_check_run(
            installation_id,
            repo,
            check_run_id,
            title=output.title,
            summary=summary,
            conclusion=conclusion.value,
            annotations=batches[-1],
        )
    except GitHubError as exc:
        if exc.status != 422:
            raise
        log.warning("annotations rejected (%s); completing the check without them", exc.message)
        client.update_check_run(
            installation_id,
            repo,
            check_run_id,
            title=output.title,
            summary=summary + "\n\n(Inline annotations could not be attached.)",
            conclusion=conclusion.value,
        )


def complete_with_error(
    client: GitHubClient,
    installation_id: int,
    repo: str,
    check_run_id: int,
    conclusion: Conclusion,
    detail: str,
) -> None:
    """Close a check run when newsoc itself failed, so it never hangs as 'in progress'."""
    client.update_check_run(
        installation_id,
        repo,
        check_run_id,
        title="newsoc could not complete this check",
        summary=f"{detail}\n\nThis is a problem on newsoc's side, not necessarily in your code.",
        conclusion=conclusion.value,
    )
