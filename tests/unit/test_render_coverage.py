"""The coverage section of the check summary and the pull request comment."""

from __future__ import annotations

from datetime import date

import pytest

from newsoc_code.findings.schema import Category, ScanStatus
from newsoc_code.policy.engine import evaluate
from newsoc_code.policy.loader import load_policy
from newsoc_code.report.render import SUPPORTED_NOTE, render_check, render_comment
from newsoc_code.scanners import checkov, osv, semgrep
from tests.factories import finding, result

TODAY = date(2026, 10, 26)
ONLY_SECRETS = "No new findings; only secrets were assessed (no SAST, SCA or IaC coverage)"
NOT_ASSESSED_BANNER = "**No code analysis ran.**"


def outcome_for(results, policy="mode: enforce\n"):
    return evaluate(load_policy(policy, TODAY), results, frozenset(), TODAY)


def na(category, reason="no applicable files"):
    return result(category, status=ScanStatus.NOT_APPLICABLE, reason=reason)


def java_repository():
    return [
        na(Category.SAST, "no JavaScript, TypeScript or Python files to analyse"),
        na(Category.SCA, "no supported dependency lockfile (npm or PyPI)"),
        result(Category.SECRETS),
        na(Category.IAC, "no Terraform or Dockerfile changes to analyse"),
    ]


def both_outputs(results, policy="mode: enforce\n"):
    out = outcome_for(results, policy)
    return out, render_check(out, results).summary, render_comment(out, results)


def coverage_section(text: str) -> str:
    """The lines from the Coverage line to the category table."""
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("**Coverage:**"))
    end = next(i for i, line in enumerate(lines) if line.startswith("| Category"))
    return "\n".join(lines[start:end])


# ---- only secrets were assessed (the unsupported-language case) -----------------------------


def test_title_and_both_outputs_make_the_missing_code_analysis_unmistakable():
    out, summary, comment = both_outputs(java_repository())
    assert out.conclusion.value == "success"  # gating is unchanged
    assert render_check(out, java_repository()).title == ONLY_SECRETS
    for text in (summary, comment):
        assert ONLY_SECRETS in text
        assert (
            "**Coverage:** assessed: secrets. Not assessed: SAST (not applicable), "
            "SCA (not applicable), IaC (not applicable)." in text
        )
        assert NOT_ASSESSED_BANNER in text
        assert "does not cover code, dependencies or infrastructure files" in text
        assert "Only secrets were checked." in text
        assert SUPPORTED_NOTE in text


def test_the_comment_headline_is_still_the_conclusion_and_the_coverage_follows_it():
    _, _, comment = both_outputs(java_repository())
    lines = comment.splitlines()
    assert lines[1] == "### newsoc security check: success"
    assert comment.index("**Coverage:**") < comment.index("| Category")


def test_verified_still_means_a_scanner_ran_and_found_nothing():
    _, summary, _ = both_outputs(java_repository())
    rows = {line.split("|")[2].strip(): line for line in summary.splitlines() if "| " in line}
    assert "Verified" in rows["secrets-scanner"] and "| 0 |" in rows["secrets-scanner"]
    for scanner in ("sast-scanner", "sca-scanner", "iac-scanner"):
        assert "Verified" not in rows[scanner]
        assert "Not assessed (" in rows[scanner]


def test_a_scanner_that_did_not_run_does_not_show_zero_findings():
    _, summary, comment = both_outputs(java_repository())
    for text in (summary, comment):
        for scanner in ("sast-scanner", "sca-scanner", "iac-scanner"):
            row = next(line for line in text.splitlines() if f"| {scanner} |" in line)
            assert row.rstrip().endswith("| - |")


def test_nothing_assessed_says_secrets_were_not_assessed_either():
    results = [na(c) for c in Category]
    _, summary, comment = both_outputs(results)
    for text in (summary, comment):
        assert "Nothing was assessed" in text
        assert "**Coverage:** assessed: none." in text
        assert "Secrets were not assessed either." in text
        assert "Only secrets were checked." not in text


def test_failed_code_analysis_is_a_coverage_gap_but_is_not_blamed_on_unsupported_languages():
    results = [
        result(Category.SAST, status=ScanStatus.FAILED, reason="semgrep exited with status 2"),
        result(Category.SCA, status=ScanStatus.TIMEOUT, reason="osv-scanner timed out"),
        result(Category.SECRETS),
        result(Category.IAC, status=ScanStatus.FAILED, reason="checkov was killed"),
    ]
    out, summary, comment = both_outputs(results, "mode: observe\n")
    assert out.title == "Not assessed: iac, sast, sca"
    for text in (summary, comment):
        assert "Not assessed: SAST (failed), SCA (timed out), IaC (failed)." in text
        assert NOT_ASSESSED_BANNER in text
        assert SUPPORTED_NOTE not in text  # the languages are supported; the scanners failed


def test_the_supported_languages_are_listed_when_any_code_gap_is_not_applicable():
    results = [
        na(Category.SAST),
        result(Category.SCA, status=ScanStatus.FAILED, reason="boom"),
        result(Category.SECRETS),
        result(Category.IAC, status=ScanStatus.FAILED, reason="boom"),
    ]
    _, summary, _ = both_outputs(results, "mode: observe\n")
    assert SUPPORTED_NOTE in summary


# ---- other situations -------------------------------------------------------------------------


def test_full_coverage_gets_a_single_short_line_and_no_banner():
    results = [result(c) for c in Category]
    out, summary, comment = both_outputs(results)
    for text in (summary, comment):
        assert "**Coverage:** all categories assessed (SAST, SCA, secrets, IaC)." in text
        assert NOT_ASSESSED_BANNER not in text and SUPPORTED_NOTE not in text
    assert out.title == "No new findings"


def test_partial_coverage_lists_the_gap_without_the_banner():
    results = [
        result(Category.SAST),
        na(Category.SCA),
        result(Category.SECRETS),
        na(Category.IAC),
    ]
    out, summary, comment = both_outputs(results)
    assert out.title == "No new findings"
    for text in (summary, comment):
        assert (
            "**Coverage:** assessed: SAST, secrets. Not assessed: SCA (not applicable), "
            "IaC (not applicable)." in text
        )
        assert NOT_ASSESSED_BANNER not in text and SUPPORTED_NOTE not in text


def test_a_blocking_secret_still_gets_the_no_code_analysis_banner():
    leak = finding(category=Category.SECRETS)
    results = [
        na(Category.SAST),
        na(Category.SCA),
        result(Category.SECRETS, [leak]),
        na(Category.IAC),
    ]
    out, summary, _ = both_outputs(results)
    assert out.title == "1 blocking finding(s)"
    assert NOT_ASSESSED_BANNER in summary


def test_no_coverage_wording_claims_the_code_is_secure_or_compliant():
    banned = ("secure", "compliant", "safe", "clean", "all clear", "no issues", "passed")
    cases = [
        java_repository(),
        [na(c) for c in Category],
        [result(c) for c in Category],
        [result(Category.SAST), na(Category.SCA), result(Category.SECRETS), na(Category.IAC)],
        [result(Category.SAST, status=ScanStatus.FAILED, reason="x"), result(Category.SECRETS)],
    ]
    for results in cases:
        _, summary, comment = both_outputs(results, "mode: observe\n")
        for text in (summary, comment):
            lowered = coverage_section(text).lower()
            assert not any(word in lowered for word in banned), lowered


# ---- escaping ---------------------------------------------------------------------------------

HOSTILE = "</details><img src=x onerror=1> @victim\n| injected | row |\nsecond line"


@pytest.mark.parametrize(
    "status", [ScanStatus.NOT_APPLICABLE, ScanStatus.FAILED, ScanStatus.TIMEOUT]
)
def test_a_hostile_scanner_reason_cannot_break_out_of_either_output(status):
    results = [
        result(Category.SAST, status=status, reason=HOSTILE),
        result(Category.SECRETS),
    ]
    _, summary, comment = both_outputs(results, "mode: observe\n")
    for text in (summary, comment):
        assert "<img" not in text and "</details>" not in text
        assert "@victim" not in text
        assert "\n| injected" not in text
        # the coverage section only ever names categories and the kind of gap
        assert "victim" not in coverage_section(text)
        # the category table is still one row per scanner
        table = [line for line in text.splitlines() if line.startswith("|")]
        assert len(table) == 4  # header, separator, sast, secrets


def test_the_coverage_text_is_independent_of_untrusted_input():
    clean = both_outputs([result(Category.SAST, status=ScanStatus.FAILED, reason="boom")])[1]
    hostile = both_outputs([result(Category.SAST, status=ScanStatus.FAILED, reason=HOSTILE)])[1]
    assert coverage_section(clean) == coverage_section(hostile)


# ---- the supported-language list matches the scanners -----------------------------------------


def test_supported_note_names_what_the_scanners_actually_cover():
    for word in ("JavaScript", "TypeScript", "Python", "npm", "PyPI", "Terraform", "Dockerfile"):
        assert word in SUPPORTED_NOTE
    assert {".js", ".ts", ".py"} <= set(semgrep.SOURCE_SUFFIXES)
    assert {"package-lock.json", "requirements.txt"} <= set(osv.LOCKFILES)
    assert set(checkov.FRAMEWORKS) == {"terraform", "dockerfile"}
