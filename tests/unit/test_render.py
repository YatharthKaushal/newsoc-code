from __future__ import annotations

from datetime import date

import pytest

from newsoc_code.findings.schema import Category, ScanStatus, Severity
from newsoc_code.policy.engine import Conclusion, evaluate
from newsoc_code.policy.loader import load_policy
from newsoc_code.report.render import (
    ANNOTATION_BATCH,
    COMMENT_MARKER,
    MAX_ANNOTATIONS,
    annotation_batches,
    md_text,
    render_check,
    render_comment,
)
from tests.factories import finding, result

TODAY = date(2026, 10, 26)


def outcome_for(results, policy="mode: enforce\n", baseline=frozenset()):
    return evaluate(load_policy(policy, TODAY), results, baseline, TODAY)


def sample_results():
    return [
        result(
            Category.SAST,
            [
                finding(
                    severity=Severity.HIGH, path="src/z.js", rule_id="newsoc.js.eval-injection"
                ),
                finding(severity=Severity.MEDIUM, path="src/a.js", rule_id="newsoc.js.other"),
            ],
        ),
        result(
            Category.SECRETS,
            [
                finding(
                    category=Category.SECRETS,
                    severity=Severity.CRITICAL,
                    path="cfg.js",
                    rule_id="github-pat",
                )
            ],
        ),
        result(Category.SCA, status=ScanStatus.FAILED, reason="database missing"),
    ]


# ---- untrusted text ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "must_not_contain"),
    [
        ("<script>alert(1)</script>", "<script>"),
        ("ping @everyone and @octocat", "@e"),
        ("a | b | c", " | "),
        ("line one\nline two\r\nline three", "\n"),
        ("text with `backticks` inside", "`"),
    ],
)
def test_md_text_neutralises_markdown_html_and_mentions(raw, must_not_contain):
    assert must_not_contain not in md_text(raw)


def test_md_text_truncates_long_text():
    out = md_text("x" * 1000, limit=50)
    assert len(out) == 50 and out.endswith("…")


def test_a_hostile_message_cannot_break_out_of_the_comment():
    nasty = finding(rule_id="r", path="a.js")
    nasty = nasty.model_copy(
        update={"message": "</details><img src=x onerror=1> @victim\n| injected | row |"}
    )
    out = outcome_for([result(findings=[nasty])])
    comment = render_comment(out, [result(findings=[nasty])])
    assert "<img" not in comment and "@victim" not in comment and "\n| injected" not in comment


# ---- the check output -------------------------------------------------------------------------


def test_summary_lists_every_scanner_and_says_not_assessed_when_one_failed():
    results = sample_results()
    check = render_check(outcome_for(results), results, rules_version="abc123")
    assert "| sast |" in check.summary and "| secrets |" in check.summary
    assert "Not assessed (database missing)" in check.summary
    assert "Rule pack: abc123" in check.summary
    assert "not a certification" in check.summary


def test_title_is_the_policy_title():
    results = sample_results()
    out = outcome_for(results)
    assert render_check(out, results).title == out.title


def test_annotations_put_blocking_findings_first_then_by_severity():
    results = sample_results()
    notes = render_check(outcome_for(results), results).annotations
    assert [n["path"] for n in notes] == ["cfg.js", "src/z.js", "src/a.js"]
    assert [n["annotation_level"] for n in notes] == ["failure", "failure", "notice"]


def test_annotation_levels_follow_the_outcome():
    f = finding(severity=Severity.HIGH)
    blocked = render_check(outcome_for([result(findings=[f])]), [result(findings=[f])]).annotations[
        0
    ]
    observed = render_check(
        outcome_for([result(findings=[f])], "mode: observe\n"), [result(findings=[f])]
    ).annotations[0]
    assert blocked["annotation_level"] == "failure" and observed["annotation_level"] == "warning"


def test_waived_and_existing_findings_are_not_annotated():
    waived, existing, fresh = finding(cwe=("CWE-1",)), finding(), finding()
    policy = (
        "mode: enforce\nwaivers:\n  - rule: CWE-1\n    expires: 2026-12-31\n    approved_by: x\n"
    )
    out = outcome_for(
        [result(findings=[waived, existing, fresh])], policy, frozenset({existing.fingerprint})
    )
    notes = render_check(out, [result(findings=[waived, existing, fresh])]).annotations
    assert len(notes) == 1


def test_annotations_are_capped_and_the_overflow_is_counted():
    many = [finding(path=f"f{i}.js", fingerprint=f"fp{i}") for i in range(MAX_ANNOTATIONS + 30)]
    check = render_check(outcome_for([result(findings=many)]), [result(findings=many)])
    assert len(check.annotations) == MAX_ANNOTATIONS
    assert check.truncated_annotations == 30


def test_annotations_are_batched_in_fifties():
    batches = annotation_batches([{"i": i} for i in range(120)])
    assert [len(b) for b in batches] == [ANNOTATION_BATCH, ANNOTATION_BATCH, 20]
    assert annotation_batches([]) == []


def test_summary_never_exceeds_the_github_limit():
    many = [
        finding(path=f"f{i}.js", fingerprint=f"fp{i}").model_copy(update={"message": "m" * 250})
        for i in range(500)
    ]
    check = render_check(outcome_for([result(findings=many)]), [result(findings=many)])
    assert len(check.summary) <= 65_535


# ---- the pull request comment -----------------------------------------------------------------


def test_comment_carries_the_marker_and_the_conclusion():
    results = sample_results()
    out = outcome_for(results)
    comment = render_comment(out, results, check_url="https://github.com/acme/widgets/runs/1")
    assert comment.startswith(COMMENT_MARKER)
    assert "failure" in comment.splitlines()[1]
    assert "https://github.com/acme/widgets/runs/1" in comment


def test_comment_shows_at_most_ten_findings():
    many = [finding(path=f"f{i}.js", fingerprint=f"fp{i}") for i in range(30)]
    comment = render_comment(outcome_for([result(findings=many)]), [result(findings=many)])
    assert comment.count("- **high**") == 10
    assert "10 of 30" in comment


def test_clean_scan_comment_says_so_without_findings_section():
    results = [result(Category.SAST), result(Category.SECRETS)]
    out = outcome_for(results)
    comment = render_comment(out, results)
    assert out.conclusion is Conclusion.SUCCESS
    assert "Top findings" not in comment and "no findings" in comment
