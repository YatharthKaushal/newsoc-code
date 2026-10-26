"""Invariants of the policy engine, checked over generated inputs (Hypothesis)."""

from __future__ import annotations

from datetime import date, timedelta

from hypothesis import given, settings
from hypothesis import strategies as st

from newsoc_code.findings.schema import Category, Confidence, ScanStatus, Severity
from newsoc_code.policy.engine import Conclusion, Outcome, evaluate
from newsoc_code.policy.loader import load_policy
from tests.factories import finding, result

TODAY = date(2026, 10, 26)
PATHS = ["src/a.js", "src/b.js", "legacy/old.js", "api/app.py"]
RULES = [("r1", ("CWE-78",)), ("r2", ("CWE-79",)), ("r3", ())]

findings_st = st.builds(
    finding,
    category=st.sampled_from(list(Category)),
    severity=st.sampled_from(list(Severity)),
    confidence=st.sampled_from(list(Confidence)),
    path=st.sampled_from(PATHS),
    fingerprint=st.text(alphabet="abcdef", min_size=1, max_size=3),
).flatmap(
    lambda f: st.sampled_from(RULES).map(
        lambda r: f.model_copy(update={"rule_id": r[0], "cwe": r[1]})
    )
)
finding_lists = st.lists(findings_st, max_size=12)
baselines = st.one_of(
    st.none(), st.frozensets(st.text(alphabet="abcdef", min_size=1, max_size=3), max_size=8)
)
severity_sets = st.sets(st.sampled_from(list(Severity)), min_size=1)

SETTINGS = settings(max_examples=150, deadline=None)


def results_for(findings):
    by_cat: dict[Category, list] = {c: [] for c in Category}
    for f in findings:
        by_cat[f.category].append(f)
    return [result(c, fs) for c, fs in by_cat.items()]


def policy(mode="enforce", block_on=("critical", "high"), new_only=True, waivers="", actions=""):
    return (
        f"mode: {mode}\ngates:\n  merge:\n    block_on: [{', '.join(block_on)}]\n"
        f"    new_findings_only: {str(new_only).lower()}\n{actions}{waivers}"
    )


def waiver(rule, expires, path="**"):
    return (
        f"waivers:\n  - rule: {rule}\n    path: '{path}'\n"
        f"    expires: {expires}\n    approved_by: sec\n"
    )


def evaluate_with(text, findings, baseline):
    return evaluate(load_policy(text, TODAY), results_for(findings), baseline, TODAY)


def blocked(out):
    return len(out.of(Outcome.BLOCKED))


@SETTINGS
@given(
    finding_lists,
    baselines,
    st.sampled_from(["r1", "r2", "CWE-78", "CWE-79"]),
    st.sampled_from(["**", "src/**", "legacy/**"]),
)
def test_adding_a_live_waiver_never_blocks_more(findings, baseline, rule, path):
    base = evaluate_with(policy(), findings, baseline)
    waived = evaluate_with(policy(waivers=waiver(rule, "2026-12-31", path)), findings, baseline)
    assert blocked(waived) <= blocked(base)


@SETTINGS
@given(finding_lists, baselines, st.sampled_from(["r1", "r2", "CWE-78", "CWE-79"]))
def test_an_expired_waiver_changes_nothing(findings, baseline, rule):
    base = evaluate_with(policy(), findings, baseline)
    stale = evaluate_with(
        policy(waivers=waiver(rule, TODAY - timedelta(days=1))), findings, baseline
    )
    assert [d.outcome for d in stale.decisions] == [d.outcome for d in base.decisions]
    assert stale.conclusion == base.conclusion


@SETTINGS
@given(finding_lists, baselines)
def test_observe_mode_never_fails_a_valid_policy(findings, baseline):
    out = evaluate_with(policy(mode="observe"), findings, baseline)
    assert out.conclusion is not Conclusion.FAILURE
    assert not out.of(Outcome.BLOCKED)


@SETTINGS
@given(finding_lists, baselines)
def test_enforce_fails_exactly_when_something_is_blocked(findings, baseline):
    out = evaluate_with(policy(), findings, baseline)
    assert (out.conclusion is Conclusion.FAILURE) == (blocked(out) > 0)


@SETTINGS
@given(finding_lists, baselines)
def test_widening_block_on_never_blocks_less(findings, baseline):
    narrow = blocked(evaluate_with(policy(block_on=("critical",)), findings, baseline))
    middle = blocked(evaluate_with(policy(block_on=("critical", "high")), findings, baseline))
    wide = blocked(
        evaluate_with(policy(block_on=("critical", "high", "medium", "low")), findings, baseline)
    )
    assert narrow <= middle <= wide


@SETTINGS
@given(
    finding_lists,
    baselines,
    st.frozensets(st.text(alphabet="abcdef", min_size=1, max_size=3), max_size=6),
)
def test_a_bigger_baseline_never_blocks_more(findings, baseline, extra):
    small = baseline or frozenset()
    base = blocked(evaluate_with(policy(), findings, small))
    bigger = blocked(evaluate_with(policy(), findings, small | extra))
    assert bigger <= base


@SETTINGS
@given(finding_lists, baselines)
def test_gating_only_new_findings_never_blocks_more_than_gating_everything(findings, baseline):
    only_new = blocked(evaluate_with(policy(new_only=True), findings, baseline))
    everything = blocked(evaluate_with(policy(new_only=False), findings, baseline))
    assert only_new <= everything


@SETTINGS
@given(finding_lists, baselines)
def test_finding_order_does_not_change_the_conclusion(findings, baseline):
    forward = evaluate_with(policy(), findings, baseline)
    backward = evaluate_with(policy(), list(reversed(findings)), baseline)
    assert forward.conclusion == backward.conclusion
    assert blocked(forward) == blocked(backward)


@SETTINGS
@given(
    finding_lists,
    baselines,
    st.sampled_from(list(Category)),
    st.sampled_from([ScanStatus.FAILED, ScanStatus.TIMEOUT]),
)
def test_a_failed_scanner_is_never_a_success(findings, baseline, category, status):
    results = [r for r in results_for(findings) if r.category is not category]
    results.append(result(category, status=status, reason="boom"))
    out = evaluate(load_policy(policy(), TODAY), results, baseline, TODAY)
    assert out.conclusion is not Conclusion.SUCCESS
