"""Coverage: which categories were assessed, and a title that never reads as a false all-clear.

Titles are asserted literally on purpose: they are part of the conformance contract.
"""

from __future__ import annotations

from datetime import date

import pytest

from newsoc_code.findings.schema import Category, ScanStatus, Severity
from newsoc_code.policy.engine import Conclusion, GapKind, evaluate
from newsoc_code.policy.loader import load_policy
from tests.factories import finding, result

TODAY = date(2026, 10, 26)
ENFORCE = "mode: enforce\n"
OBSERVE = "mode: observe\n"
ONLY_SECRETS = "No new findings; only secrets were assessed (no SAST, SCA or IaC coverage)"


def run(policy_text, results, baseline=frozenset()):
    return evaluate(load_policy(policy_text, TODAY), results, baseline, TODAY)


def na(category, reason="nothing to analyse"):
    return result(category, status=ScanStatus.NOT_APPLICABLE, reason=reason)


def broken(category, status=ScanStatus.FAILED, reason="scanner crashed"):
    return result(category, status=status, reason=reason)


def java_repository():
    """What the real replay of a 100% Java repository produced: only the secrets scanner ran."""
    return [
        na(Category.SAST, "no JavaScript, TypeScript or Python files to analyse"),
        na(Category.SCA, "no supported dependency lockfile (npm or PyPI)"),
        result(Category.SECRETS),
        na(Category.IAC, "no Terraform or Dockerfile changes to analyse"),
    ]


# ---- the title -------------------------------------------------------------------------------


@pytest.mark.parametrize("policy", [ENFORCE, OBSERVE, None])
def test_only_secrets_assessed_still_succeeds_but_the_title_says_what_was_assessed(policy):
    out = run(policy, java_repository())
    assert out.conclusion is Conclusion.SUCCESS  # gating is unchanged: a green check passes
    assert out.title == ONLY_SECRETS


@pytest.mark.parametrize("assessed", [Category.SAST, Category.SCA, Category.IAC])
def test_any_assessed_code_analysis_category_keeps_the_plain_title(assessed):
    others = [c for c in Category if c is not assessed]
    results = [result(assessed)] + [na(c) for c in others]
    out = run(ENFORCE, results)
    assert out.conclusion is Conclusion.SUCCESS
    assert out.title == "No new findings"


def test_sast_assessed_with_everything_else_not_applicable_keeps_the_plain_title():
    out = run(ENFORCE, [result(Category.SAST), na(Category.SCA), na(Category.IAC)])
    assert out.title == "No new findings"
    assert [c.value for c in out.coverage.assessed] == ["sast"]


def test_all_categories_failed_is_never_success_and_never_says_no_new_findings():
    everything = [broken(c) for c in Category]
    observe = run(OBSERVE, everything)
    assert observe.conclusion is Conclusion.NEUTRAL
    assert observe.title == "Not assessed: iac, sast, sca, secrets"
    enforce = run(ENFORCE, everything)
    assert enforce.conclusion is Conclusion.ACTION_REQUIRED
    assert enforce.title == "Not assessed: secrets (re-run required)"  # unchanged wording
    for out in (observe, enforce):
        assert "No new findings" not in out.title
        assert out.coverage.assessed == ()
        assert {g.kind for g in out.coverage.gaps} == {GapKind.FAILED}


def test_nothing_assessed_because_nothing_applied_is_not_called_an_all_clear():
    out = run(ENFORCE, [na(c) for c in Category])
    assert out.conclusion is Conclusion.SUCCESS
    assert out.title == "Nothing was assessed (no scanner had anything to analyse)"


def test_an_empty_scan_is_reported_as_nothing_assessed_with_no_scanner_result():
    out = run(ENFORCE, [])
    assert out.conclusion is Conclusion.SUCCESS
    assert out.title == "Nothing was assessed (no scanner had anything to analyse)"
    assert {g.kind for g in out.coverage.gaps} == {GapKind.NOT_RUN}


def test_titles_for_findings_and_failures_are_unchanged_when_only_secrets_ran():
    blocked = finding(category=Category.SECRETS, severity=Severity.CRITICAL)
    code = [na(Category.SAST), na(Category.SCA), na(Category.IAC)]
    out = run(ENFORCE, [result(Category.SECRETS, [blocked]), *code])
    assert out.title == "1 blocking finding(s)"
    out = run(OBSERVE, [result(Category.SECRETS, [blocked]), *code])
    assert out.title == "Observe mode: 1 finding(s) would block"
    low = finding(category=Category.SECRETS, severity=Severity.LOW)
    out = run(ENFORCE, [result(Category.SECRETS, [low]), *code])
    assert out.title == "Findings reported; none block"
    out = run(ENFORCE, [broken(Category.SECRETS), *code])
    assert out.title == "Not assessed: secrets (re-run required)"


def test_a_baselined_finding_does_not_change_the_rule():
    old = finding(category=Category.SECRETS)
    results = [result(Category.SECRETS, [old]), na(Category.SAST)]
    out = run(ENFORCE, results, baseline=frozenset({old.fingerprint}))
    assert out.conclusion is Conclusion.SUCCESS
    assert out.title == ONLY_SECRETS


def test_titles_are_short_and_never_claim_security_or_compliance():
    for results in (java_repository(), [], [na(c) for c in Category]):
        title = run(ENFORCE, results).title
        assert len(title) <= 80
        lowered = title.lower()
        assert not any(w in lowered for w in ("secure", "compliant", "safe", "clean", "all clear"))


# ---- the coverage summary ---------------------------------------------------------------------


def test_coverage_lists_assessed_categories_and_each_gap_with_its_reason():
    cov = run(ENFORCE, java_repository()).coverage
    assert cov.assessed == (Category.SECRETS,)
    assert not cov.code_analysis_assessed
    assert [(g.category, g.kind) for g in cov.gaps] == [
        (Category.SAST, GapKind.NOT_APPLICABLE),
        (Category.SCA, GapKind.NOT_APPLICABLE),
        (Category.IAC, GapKind.NOT_APPLICABLE),
    ]
    assert cov.gaps[0].reason == "no JavaScript, TypeScript or Python files to analyse"


def test_coverage_tells_not_applicable_failed_and_timed_out_apart():
    out = run(
        OBSERVE,
        [
            na(Category.SAST),
            broken(Category.SCA, ScanStatus.FAILED, "osv-scanner exited with status 2"),
            result(Category.SECRETS),
            broken(Category.IAC, ScanStatus.TIMEOUT, "checkov timed out"),
        ],
    )
    kinds = {g.category: (g.kind, g.reason) for g in out.coverage.gaps}
    assert kinds == {
        Category.SAST: (GapKind.NOT_APPLICABLE, "nothing to analyse"),
        Category.SCA: (GapKind.FAILED, "osv-scanner exited with status 2"),
        Category.IAC: (GapKind.TIMED_OUT, "checkov timed out"),
    }
    assert out.coverage.assessed == (Category.SECRETS,)


def test_a_failure_wins_over_an_ok_result_in_the_same_category():
    two_sast = [result(Category.SAST), broken(Category.SAST)]
    out = run(OBSERVE, two_sast)
    assert Category.SAST not in out.coverage.assessed
    assert [g.kind for g in out.coverage.gaps if g.category is Category.SAST] == [GapKind.FAILED]


def test_a_category_with_no_scanner_result_is_a_gap_not_an_assumed_pass():
    out = run(ENFORCE, [result(Category.SAST)])
    missing = {g.category: g.kind for g in out.coverage.gaps}
    assert missing == {
        Category.SCA: GapKind.NOT_RUN,
        Category.SECRETS: GapKind.NOT_RUN,
        Category.IAC: GapKind.NOT_RUN,
    }


def test_full_coverage_has_no_gaps():
    out = run(ENFORCE, [result(c) for c in Category])
    assert out.coverage.gaps == ()
    assert set(out.coverage.assessed) == set(Category)
    assert out.title == "No new findings"
