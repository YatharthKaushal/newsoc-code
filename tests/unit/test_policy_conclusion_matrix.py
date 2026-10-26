"""The coverage change must not move a single check conclusion.

``tests/golden/policy/conclusions_before_coverage.json`` records the conclusion the policy engine
gave, at commit ba49715 (before coverage reporting existed), for every combination of

* six policies (none, observe, enforce, either with ``on_scanner_error: block``, and an
  invalid one), and
* six states for each of the four categories: clean, blocking finding, warning finding, finding
  already on the base branch, scanner failed, not applicable.

That is 6 x 6^4 = 7,776 inputs that cover every branch of the conclusion logic. The file was
produced by running the engine as it was at ba49715 over ``matrix_rows()``; it is not
regenerated from the current engine, so this test fails if a later change moves any conclusion.
It is a characterisation test for refactoring safety; the language-neutral expectations that a
Go implementation must meet are the hand-written vectors in ``contracts/vectors/policy``.
"""

from __future__ import annotations

import itertools
import json
import re
from collections.abc import Callable, Iterator
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from newsoc_code.findings.schema import Category, ScanResult, ScanStatus, Severity
from newsoc_code.policy.engine import evaluate
from newsoc_code.policy.loader import load_policy
from tests.factories import finding

GOLDEN = Path(__file__).parents[1] / "golden" / "policy" / "conclusions_before_coverage.json"
TODAY = date(2026, 10, 26)

CATEGORIES = (Category.SAST, Category.SCA, Category.SECRETS, Category.IAC)
STATES = "cbwefn"  # clean, blocking, warning, existing, failed, not applicable
ASSESSED_STATES = "cbwe"
POLICIES: dict[str, str | None] = {
    "default": None,
    "observe": "mode: observe\n",
    "enforce": "mode: enforce\n",
    "enforce_block_errors": "mode: enforce\non_scanner_error: block\n",
    "observe_block_errors": "mode: observe\non_scanner_error: block\n",
    "invalid": "mode: yolo\n",
}
LETTER = {"success": "S", "neutral": "N", "failure": "F", "action_required": "A"}


def _results(states: tuple[str, ...]) -> tuple[list[ScanResult], frozenset[str]]:
    results: list[ScanResult] = []
    baseline: set[str] = set()
    for category, state in zip(CATEGORIES, states, strict=True):
        fingerprint = f"{category.value}-{state}"
        if state in "bwe":
            severity = Severity.MEDIUM if state == "w" else Severity.HIGH
            findings = [
                finding(category=category, severity=severity, fingerprint=fingerprint),
            ]
            if state == "e":
                baseline.add(fingerprint)
        else:
            findings = []
        status = {
            "f": ScanStatus.FAILED,
            "n": ScanStatus.NOT_APPLICABLE,
        }.get(state, ScanStatus.OK)
        results.append(
            ScanResult(
                scanner=f"{category.value}-scanner",
                category=category,
                status=status,
                findings=findings,
                reason=None if status is ScanStatus.OK else "state under test",
            )
        )
    return results, frozenset(baseline)


def matrix_rows() -> Iterator[tuple[str, tuple[str, ...]]]:
    """Every (policy name, per-category states) input, in a fixed order."""
    for policy in POLICIES:
        for states in itertools.product(STATES, repeat=len(CATEGORIES)):
            yield policy, states


def conclusions_with(evaluate_fn: Callable[..., Any]) -> dict[str, str]:
    """One letter per input, grouped by policy; ``evaluate_fn`` is an engine's ``evaluate``."""
    out: dict[str, list[str]] = {name: [] for name in POLICIES}
    for policy, states in matrix_rows():
        results, baseline = _results(states)
        outcome = evaluate_fn(load_policy(POLICIES[policy], TODAY), results, baseline, TODAY)
        out[policy].append(LETTER[outcome.conclusion.value])
    return {name: "".join(letters) for name, letters in out.items()}


def test_the_recorded_matrix_covers_every_input():
    golden = json.loads(GOLDEN.read_text())
    assert golden["generated_from"].startswith("ba49715")
    assert set(golden["conclusions"]) == set(POLICIES)
    assert {len(v) for v in golden["conclusions"].values()} == {len(STATES) ** len(CATEGORIES)}
    # all four conclusions occur, so the matrix is not trivially "everything is neutral"
    assert set("".join(golden["conclusions"].values())) == set(LETTER.values())


def test_no_conclusion_differs_from_the_one_before_the_coverage_change():
    recorded = json.loads(GOLDEN.read_text())["conclusions"]
    now = conclusions_with(evaluate)
    inputs = list(itertools.product(STATES, repeat=len(CATEGORIES)))
    for policy, letters in recorded.items():
        changed = [
            ("".join(states), was, is_now)
            for states, was, is_now in zip(inputs, letters, now[policy], strict=True)
            if was != is_now
        ]
        assert not changed, f"{policy}: conclusions moved (states, was, now): {changed[:5]}"


# ---- titles: only the plain all-clear may change ---------------------------------------------

UNCHANGED_TITLES = [
    r"\d+ blocking finding\(s\)",
    r"Observe mode: \d+ finding\(s\) would block",
    r"Not assessed: [a-z, ]+( \(re-run required\))?",
    r"Findings reported; none block",
    r"Policy invalid; strict defaults applied until it is fixed",
]
ONLY_SECRETS = "No new findings; only secrets were assessed (no SAST, SCA or IaC coverage)"
NOTHING = "Nothing was assessed (no scanner had anything to analyse)"


def expected_all_clear_title(states: tuple[str, ...]) -> str:
    assessed = {c for c, s in zip(CATEGORIES, states, strict=True) if s in ASSESSED_STATES}
    if assessed & {Category.SAST, Category.SCA, Category.IAC}:
        return "No new findings"
    return ONLY_SECRETS if Category.SECRETS in assessed else NOTHING


@pytest.mark.parametrize("policy", POLICIES)
def test_across_the_whole_matrix_only_the_plain_all_clear_title_changes(policy):
    for name, states in matrix_rows():
        if name != policy:
            continue
        results, baseline = _results(states)
        out = evaluate(load_policy(POLICIES[policy], TODAY), results, baseline, TODAY)
        if out.conclusion.value == "success":
            assert out.title == expected_all_clear_title(states), (policy, states)
        else:
            assert any(re.fullmatch(p, out.title) for p in UNCHANGED_TITLES), (
                policy,
                states,
                out.title,
            )
