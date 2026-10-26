"""Publishing check runs and upserting the PR comment, against a recording fake client."""

from __future__ import annotations

import pytest

from newsoc_code.github.checks import complete_with_error, publish_result
from newsoc_code.github.client import GitHubError
from newsoc_code.github.comments import upsert_summary_comment
from newsoc_code.policy.engine import Conclusion
from newsoc_code.report.render import COMMENT_MARKER, CheckOutput

APP_ID = 777


class FakeClient:
    app_id = APP_ID

    def __init__(self, *, comments=None, fail_update_with=None, fail_known_with=None):
        self.updates: list[dict] = []
        self.comments = comments or []
        self.calls: list[tuple] = []
        self._fail_update_with = fail_update_with
        self._fail_known_with = fail_known_with

    def update_check_run(self, installation_id, repo, run_id, **kw):
        self.updates.append(kw)
        if self._fail_update_with and kw.get("annotations"):
            raise self._fail_update_with

    def list_comments(self, installation_id, repo, number):
        self.calls.append(("list",))
        return self.comments

    def create_comment(self, installation_id, repo, number, body):
        self.calls.append(("create", body))
        return 9001

    def update_comment(self, installation_id, repo, comment_id, body):
        self.calls.append(("update", comment_id, body))
        if self._fail_known_with and comment_id == 55:
            raise self._fail_known_with


def note(i):
    return {
        "path": f"f{i}.js",
        "start_line": 1,
        "end_line": 1,
        "annotation_level": "failure",
        "message": "m",
    }


def output(n_annotations, truncated=0):
    return CheckOutput("title", "summary", [note(i) for i in range(n_annotations)], truncated)


# ---- check runs --------------------------------------------------------------------------------


def test_annotations_go_in_fifties_and_the_conclusion_rides_the_last_request():
    client = FakeClient()
    publish_result(client, 1, "a/b", 10, output(120), Conclusion.FAILURE)

    assert [len(u.get("annotations") or []) for u in client.updates] == [50, 50, 20]
    assert [u.get("conclusion") for u in client.updates] == [None, None, "failure"]


def test_no_annotations_still_completes_the_check():
    client = FakeClient()
    publish_result(client, 1, "a/b", 10, output(0), Conclusion.SUCCESS)
    assert len(client.updates) == 1 and client.updates[0]["conclusion"] == "success"


def test_exactly_fifty_annotations_is_a_single_request():
    client = FakeClient()
    publish_result(client, 1, "a/b", 10, output(50), Conclusion.NEUTRAL)
    assert len(client.updates) == 1 and client.updates[0]["conclusion"] == "neutral"


def test_rejected_annotations_do_not_leave_the_check_hanging():
    client = FakeClient(fail_update_with=GitHubError(422, "Invalid request: path not found"))
    publish_result(client, 1, "a/b", 10, output(5), Conclusion.FAILURE)

    final = client.updates[-1]
    assert final["conclusion"] == "failure" and not final.get("annotations")
    assert "could not be attached" in final["summary"]


def test_other_errors_are_not_swallowed():
    client = FakeClient(fail_update_with=GitHubError(500, "server error"))
    with pytest.raises(GitHubError):
        publish_result(client, 1, "a/b", 10, output(5), Conclusion.FAILURE)


def test_overflow_is_mentioned_in_the_summary():
    client = FakeClient()
    publish_result(client, 1, "a/b", 10, output(3, truncated=40), Conclusion.FAILURE)
    assert "40 more finding(s)" in client.updates[-1]["summary"]


def test_complete_with_error_closes_the_run_with_the_given_conclusion():
    client = FakeClient()
    complete_with_error(client, 1, "a/b", 10, Conclusion.NEUTRAL, "internal error: boom")
    update = client.updates[0]
    assert update["conclusion"] == "neutral"
    assert "boom" in update["summary"] and "newsoc's side" in update["summary"]


# ---- the comment -------------------------------------------------------------------------------


def ours(comment_id, body=COMMENT_MARKER + " old"):
    return {"id": comment_id, "body": body, "performed_via_github_app": {"id": APP_ID}}


def test_a_new_comment_is_created_when_none_exists():
    client = FakeClient(comments=[{"id": 1, "body": "hello", "performed_via_github_app": None}])
    assert upsert_summary_comment(client, 1, "a/b", 5, "NEW") == 9001
    assert client.calls[-1] == ("create", "NEW")


def test_an_existing_comment_is_found_by_marker_and_updated_in_place():
    client = FakeClient(comments=[{"id": 1, "body": "hi"}, ours(42)])
    assert upsert_summary_comment(client, 1, "a/b", 5, "NEW") == 42
    assert ("update", 42, "NEW") in client.calls and not any(c[0] == "create" for c in client.calls)


def test_a_remembered_comment_id_is_updated_without_listing():
    client = FakeClient()
    assert upsert_summary_comment(client, 1, "a/b", 5, "NEW", known_comment_id=42) == 42
    assert client.calls == [("update", 42, "NEW")]


def test_a_deleted_comment_falls_back_to_search_then_create():
    client = FakeClient(fail_known_with=GitHubError(404, "Not Found"))
    assert upsert_summary_comment(client, 1, "a/b", 5, "NEW", known_comment_id=55) == 9001
    assert client.calls[0] == ("update", 55, "NEW") and ("list",) in client.calls


def test_someone_elses_comment_with_our_marker_is_never_edited():
    spoof = {
        "id": 7,
        "body": COMMENT_MARKER + " pasted by a user",
        "performed_via_github_app": None,
    }
    other_app = {"id": 8, "body": COMMENT_MARKER, "performed_via_github_app": {"id": 123}}
    client = FakeClient(comments=[spoof, other_app])
    assert upsert_summary_comment(client, 1, "a/b", 5, "NEW") == 9001
    assert not any(c[0] == "update" for c in client.calls)


def test_unexpected_errors_updating_a_known_comment_propagate():
    client = FakeClient(fail_known_with=GitHubError(500, "boom"))
    with pytest.raises(GitHubError):
        upsert_summary_comment(client, 1, "a/b", 5, "NEW", known_comment_id=55)
