"""The decision formula and conclusion mapping, one behaviour per test."""

from __future__ import annotations

from datetime import date

from newsoc_code.findings.schema import Category, Confidence, ScanStatus, Severity
from newsoc_code.policy.engine import Conclusion, Outcome, evaluate
from newsoc_code.policy.loader import load_policy
from tests.factories import finding, result

TODAY = date(2026, 10, 26)
ENFORCE = "mode: enforce\n"


def run(policy_text, results, baseline=frozenset(), today=TODAY):
    return evaluate(load_policy(policy_text, today), results, baseline, today)


def only(outcome):
    return outcome.decisions[0].outcome


# ---- the blocking formula ---------------------------------------------------------------------


def test_clean_scan_succeeds():
    out = run(ENFORCE, [result(Category.SAST), result(Category.SECRETS)])
    assert out.conclusion is Conclusion.SUCCESS


def test_new_high_severity_sast_finding_blocks_in_enforce_mode():
    out = run(ENFORCE, [result(findings=[finding()])])
    assert only(out) is Outcome.BLOCKED
    assert out.conclusion is Conclusion.FAILURE
    assert out.title == "1 blocking finding(s)"


def test_same_finding_in_observe_mode_is_reported_but_never_fails():
    out = run("mode: observe\n", [result(findings=[finding()])])
    assert only(out) is Outcome.WOULD_BLOCK
    assert out.conclusion is Conclusion.NEUTRAL
    assert "would block" in out.title


def test_default_policy_is_observe_so_a_fresh_install_cannot_break_ci():
    out = run(None, [result(findings=[finding(severity=Severity.CRITICAL)])])
    assert out.conclusion is Conclusion.NEUTRAL


def test_baselined_finding_does_not_block_when_only_new_findings_gate():
    f = finding()
    out = run(ENFORCE, [result(findings=[f])], baseline=frozenset({f.fingerprint}))
    assert only(out) is Outcome.BASELINED
    assert out.conclusion is Conclusion.SUCCESS


def test_baselined_finding_blocks_when_new_findings_only_is_off():
    f = finding()
    text = ENFORCE + "gates:\n  merge:\n    new_findings_only: false\n"
    out = run(text, [result(findings=[f])], baseline=frozenset({f.fingerprint}))
    assert only(out) is Outcome.BLOCKED


def test_unavailable_baseline_treats_everything_as_new_and_says_so():
    out = run(ENFORCE, [result(findings=[finding()])], baseline=None)
    assert only(out) is Outcome.BLOCKED
    assert any("baseline unavailable" in n for n in out.notes)


def test_low_confidence_findings_never_block():
    out = run(
        ENFORCE, [result(findings=[finding(confidence=Confidence.LOW, severity=Severity.CRITICAL)])]
    )
    assert only(out) is Outcome.WARNED
    assert out.conclusion is Conclusion.NEUTRAL


def test_medium_confidence_findings_can_block():
    out = run(ENFORCE, [result(findings=[finding(confidence=Confidence.MEDIUM)])])
    assert only(out) is Outcome.BLOCKED


def test_severity_below_the_threshold_only_warns():
    out = run(ENFORCE, [result(findings=[finding(severity=Severity.MEDIUM)])])
    assert only(out) is Outcome.WARNED
    assert out.conclusion is Conclusion.NEUTRAL


def test_iac_defaults_to_warn_so_it_does_not_block():
    f = finding(category=Category.IAC, severity=Severity.CRITICAL)
    out = run(ENFORCE, [result(Category.IAC, [f])])
    assert only(out) is Outcome.WARNED


def test_iac_blocks_when_the_repository_opts_in():
    f = finding(category=Category.IAC, severity=Severity.CRITICAL)
    out = run(ENFORCE + "actions:\n  iac: block\n", [result(Category.IAC, [f])])
    assert only(out) is Outcome.BLOCKED


# ---- waivers ----------------------------------------------------------------------------------


def waiver_policy(rule, expires, path="**"):
    return (
        f"{ENFORCE}waivers:\n"
        f"  - rule: {rule}\n"
        f"    path: '{path}'\n"
        f"    expires: {expires}\n"
        "    approved_by: sec\n"
    )


def test_waiver_by_rule_id_cwe_and_vulnerability_alias():
    cases = [
        ("newsoc.js.exec-concat", finding()),
        ("CWE-78", finding()),
        (
            "GHSA-aaaa-bbbb-cccc",
            finding(
                category=Category.SCA,
                rule_id="CVE-2020-1",
                vuln_ids=("CVE-2020-1", "GHSA-aaaa-bbbb-cccc"),
            ),
        ),
        (
            "cve-2020-1",
            finding(category=Category.SCA, rule_id="CVE-2020-1", vuln_ids=("CVE-2020-1",)),
        ),  # case-insensitive
    ]
    for rule, f in cases:
        out = run(waiver_policy(rule, "2026-12-31"), [result(f.category, [f])])
        assert only(out) is Outcome.WAIVED, rule
        assert out.decisions[0].waiver.approved_by == "sec"
        assert out.conclusion is Conclusion.SUCCESS


def test_waiver_is_valid_through_its_expiry_date_and_ignored_the_day_after():
    f = finding()
    on_expiry = run(waiver_policy("CWE-78", "2026-10-26"), [result(findings=[f])])
    assert only(on_expiry) is Outcome.WAIVED
    day_after = run(waiver_policy("CWE-78", "2026-10-25"), [result(findings=[f])])
    assert only(day_after) is Outcome.BLOCKED
    assert len(day_after.expired_waivers) == 1
    assert any("expired" in n for n in day_after.notes)


def test_waiver_path_glob_must_match():
    inside = finding(path="legacy/old/handler.js")
    outside = finding(path="src/new/handler.js")
    out = run(
        waiver_policy("CWE-78", "2026-12-31", "legacy/**"), [result(findings=[inside, outside])]
    )
    assert [d.outcome for d in out.decisions] == [Outcome.WAIVED, Outcome.BLOCKED]


def test_waiver_for_another_rule_does_nothing():
    out = run(waiver_policy("CWE-79", "2026-12-31"), [result(findings=[finding()])])
    assert only(out) is Outcome.BLOCKED


# ---- scanners that fail or do not apply -------------------------------------------------------


def failed(category, reason="scanner crashed"):
    return result(category, status=ScanStatus.FAILED, reason=reason)


def test_secrets_scanner_failure_fails_closed_in_enforce_mode_even_with_default_error_handling():
    out = run(ENFORCE, [failed(Category.SECRETS), result(Category.SAST)])
    assert out.conclusion is Conclusion.ACTION_REQUIRED
    assert "secrets" in out.title


def test_other_scanner_failures_are_neutral_unless_the_policy_says_block():
    assert run(ENFORCE, [failed(Category.SAST)]).conclusion is Conclusion.NEUTRAL
    strict = run(ENFORCE + "on_scanner_error: block\n", [failed(Category.SAST)])
    assert strict.conclusion is Conclusion.ACTION_REQUIRED


def test_failed_scanner_in_a_warn_only_category_never_requires_action():
    out = run(ENFORCE + "on_scanner_error: block\n", [failed(Category.IAC)])  # iac defaults to warn
    assert out.conclusion is Conclusion.NEUTRAL


def test_observe_mode_never_fails_closed_on_scanner_errors():
    assert run("mode: observe\n", [failed(Category.SECRETS)]).conclusion is Conclusion.NEUTRAL


def test_a_failed_scanner_is_never_reported_as_success():
    out = run(ENFORCE, [failed(Category.SAST), result(Category.SECRETS)])
    assert out.conclusion is not Conclusion.SUCCESS
    status = next(c for c in out.categories if c.category is Category.SAST)
    assert status.assessment.value == "Not assessed" and status.failed


def test_not_applicable_categories_do_not_prevent_success():
    skipped = result(Category.IAC, status=ScanStatus.NOT_APPLICABLE, reason="no Terraform files")
    out = run(ENFORCE, [result(Category.SAST), skipped])
    assert out.conclusion is Conclusion.SUCCESS
    status = next(c for c in out.categories if c.category is Category.IAC)
    assert status.assessment.value == "Not assessed" and not status.failed


def test_a_block_beats_a_scanner_failure():
    out = run(ENFORCE, [result(findings=[finding()]), failed(Category.SECRETS)])
    assert out.conclusion is Conclusion.FAILURE


# ---- invalid policy -------------------------------------------------------------------------


def test_invalid_policy_fails_even_when_the_scan_is_clean():
    out = run("mode: yolo\n", [result(Category.SAST)])
    assert out.conclusion is Conclusion.FAILURE
    assert "Policy invalid" in out.title


def test_invalid_policy_blocks_findings_it_would_otherwise_only_observe():
    out = run("version: 99\n", [result(findings=[finding()])])
    assert only(out) is Outcome.BLOCKED  # strict defaults apply while the file is broken
