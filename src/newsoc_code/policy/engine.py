"""The policy engine: findings + policy + baseline + date -> decisions and a check conclusion.

A pure function: no clock, no network, no files. That is what makes it testable with shared
conformance vectors (``contracts/vectors/policy``) that a future Go endpoint agent can run too.

Decision for one finding::

    blocks = in_scope and not waived and action(category) == block
             and severity in block_on and confidence >= medium

Conclusions use GitHub's check-run vocabulary. ``neutral`` PASSES a required status check, so
anything that must stop a merge is ``failure`` or ``action_required``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from enum import StrEnum
from functools import lru_cache
from typing import Any

import pathspec

from newsoc_code.findings.schema import (
    AssessmentStatus,
    Category,
    Confidence,
    Finding,
    ScanResult,
    ScanStatus,
)
from newsoc_code.policy.loader import PolicyLoad
from newsoc_code.policy.schema import Action, Mode, Policy, Waiver


class Conclusion(StrEnum):
    SUCCESS = "success"
    NEUTRAL = "neutral"  # passes a required check
    FAILURE = "failure"
    ACTION_REQUIRED = "action_required"


class Outcome(StrEnum):
    BLOCKED = "blocked"  # enforce mode: fails the check
    WOULD_BLOCK = "would_block"  # observe mode: reported, does not fail
    WARNED = "warned"
    WAIVED = "waived"
    BASELINED = "baselined"  # already present on the base branch


@dataclass(frozen=True)
class Decision:
    finding: Finding
    outcome: Outcome
    waiver: Waiver | None = None


@dataclass(frozen=True)
class CategoryStatus:
    category: Category
    scanner: str
    assessment: AssessmentStatus
    detail: str = ""
    failed: bool = False  # the scanner crashed, timed out or produced unusable output
    fail_closed: bool = False  # ... and the policy treats that category as blocking


@dataclass
class PolicyOutcome:
    conclusion: Conclusion
    title: str
    decisions: list[Decision] = field(default_factory=list)
    categories: list[CategoryStatus] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    expired_waivers: list[Waiver] = field(default_factory=list)

    def of(self, *outcomes: Outcome) -> list[Decision]:
        return [d for d in self.decisions if d.outcome in outcomes]

    @property
    def blocking(self) -> list[Decision]:
        return self.of(Outcome.BLOCKED)


@lru_cache(maxsize=256)
def _spec(pattern: str) -> pathspec.PathSpec[Any]:
    return pathspec.PathSpec.from_lines("gitignore", [pattern])


def waiver_matches(waiver: Waiver, finding: Finding) -> bool:
    """A waiver names a rule id, CWE, CVE or GHSA, and a path glob."""
    wanted = waiver.rule.strip().lower()
    names = {
        finding.rule_id.lower(),
        *(c.lower() for c in finding.cwe),
        *(v.lower() for v in finding.vuln_ids),
    }
    return wanted in names and _spec(waiver.path).match_file(finding.path)


def evaluate(
    load: PolicyLoad,
    results: list[ScanResult],
    baseline: frozenset[str] | None,
    today: date,
) -> PolicyOutcome:
    """``baseline`` holds fingerprints present on the base branch; ``None`` means unavailable."""
    policy = load.policy
    notes = [f"policy warning: {w}" for w in load.warnings] + [
        f"policy error: {e}" for e in load.errors
    ]
    if (note := load.title_note) is not None:
        notes.insert(0, note)
    if policy.merge.new_findings_only and baseline is None:
        notes.append("baseline unavailable: every finding is treated as new")

    categories = [_category_status(policy, r) for r in results]
    decisions: list[Decision] = []
    expired: list[Waiver] = []
    for result in results:
        for finding in result.findings:
            decision, stale = _decide(policy, finding, baseline, today)
            decisions.append(decision)
            expired += [w for w in stale if w not in expired]

    if expired:
        notes += [
            f"waiver for {w.rule} on {w.path} expired on {w.expires} and was ignored"
            for w in expired
        ]

    conclusion, title = _conclude(load, policy.mode, decisions, categories)
    return PolicyOutcome(conclusion, title, decisions, categories, notes, expired)


def _decide(
    policy: Policy, finding: Finding, baseline: frozenset[str] | None, today: date
) -> tuple[Decision, list[Waiver]]:
    matching = [w for w in policy.waivers if waiver_matches(w, finding)]
    live = [w for w in matching if w.expires >= today]  # valid through the expiry date, inclusive
    stale = [w for w in matching if w.expires < today]
    if live:
        return Decision(finding, Outcome.WAIVED, waiver=live[0]), stale
    if policy.merge.new_findings_only and baseline is not None and finding.fingerprint in baseline:
        return Decision(finding, Outcome.BASELINED), stale
    would_block = (
        policy.action_for(finding.category) is Action.BLOCK
        and finding.severity in policy.merge.block_on
        and finding.confidence.rank >= Confidence.MEDIUM.rank
    )
    if not would_block:
        return Decision(finding, Outcome.WARNED), stale
    outcome = Outcome.BLOCKED if policy.mode is Mode.ENFORCE else Outcome.WOULD_BLOCK
    return Decision(finding, outcome), stale


def _category_status(policy: Policy, result: ScanResult) -> CategoryStatus:
    assessment = result.assessment()
    if result.status is ScanStatus.NOT_APPLICABLE:
        return CategoryStatus(
            result.category, result.scanner, assessment, result.reason or "no applicable files"
        )
    if result.status is ScanStatus.OK:
        return CategoryStatus(result.category, result.scanner, assessment)
    blocking = policy.action_for(result.category) is Action.BLOCK
    # Secrets always fail closed when set to block; other categories follow on_scanner_error.
    fail_closed = blocking and (
        policy.on_scanner_error is Action.BLOCK or result.category is Category.SECRETS
    )
    return CategoryStatus(
        result.category,
        result.scanner,
        assessment,
        result.reason or "scanner failed",
        failed=True,
        fail_closed=fail_closed,
    )


def _conclude(
    load: PolicyLoad, mode: Mode, decisions: list[Decision], categories: list[CategoryStatus]
) -> tuple[Conclusion, str]:
    if load.invalid:
        return Conclusion.FAILURE, "Policy invalid; strict defaults applied until it is fixed"
    blocked = [d for d in decisions if d.outcome is Outcome.BLOCKED]
    if blocked:
        return Conclusion.FAILURE, f"{len(blocked)} blocking finding(s)"
    fail_closed = [c for c in categories if c.fail_closed]
    if fail_closed and mode is Mode.ENFORCE:
        names = ", ".join(sorted({c.category.value for c in fail_closed}))
        return Conclusion.ACTION_REQUIRED, f"Not assessed: {names} (re-run required)"
    would_block = [d for d in decisions if d.outcome is Outcome.WOULD_BLOCK]
    if would_block:
        return Conclusion.NEUTRAL, f"Observe mode: {len(would_block)} finding(s) would block"
    failed = [c for c in categories if c.failed]
    if failed:
        names = ", ".join(sorted({c.category.value for c in failed}))
        return Conclusion.NEUTRAL, f"Not assessed: {names}"
    if any(d.outcome is Outcome.WARNED for d in decisions):
        return Conclusion.NEUTRAL, "Findings reported; none block"
    return Conclusion.SUCCESS, "No new findings"
