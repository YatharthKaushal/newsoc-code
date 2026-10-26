"""The policy engine: findings + policy + baseline + date -> decisions and a check conclusion.

A pure function: no clock, no network, no files. That is what makes it testable with shared
conformance vectors (``contracts/vectors/policy``) that a future Go endpoint agent can run too.

Decision for one finding::

    blocks = in_scope and not waived and action(category) == block
             and severity in block_on and confidence >= medium

Conclusions use GitHub's check-run vocabulary. ``neutral`` PASSES a required status check, so
anything that must stop a merge is ``failure`` or ``action_required``.

Coverage is presentation only. ``Coverage`` records which categories were assessed and why the
others were not, and the plain all-clear title is replaced when no code-analysis category was
assessed (a green check must not suggest that code was reviewed when only secrets were
scanned). Nothing about coverage changes which conclusion an input produces.
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
    status: ScanStatus = ScanStatus.OK  # what the scanner reported; says why it was not assessed


# Categories that analyse code, dependencies or infrastructure files. Secrets scanning reads
# every file whatever its language, so a clean secrets result says nothing about whether the
# code itself was analysed.
CODE_ANALYSIS = frozenset({Category.SAST, Category.SCA, Category.IAC})

ONLY_SECRETS_TITLE = "No new findings; only secrets were assessed (no SAST, SCA or IaC coverage)"
NOTHING_ASSESSED_TITLE = "Nothing was assessed (no scanner had anything to analyse)"


class GapKind(StrEnum):
    """Why a category was not assessed."""

    NOT_APPLICABLE = "not applicable"  # the scanner had nothing to look at
    FAILED = "failed"
    TIMED_OUT = "timed out"
    NOT_RUN = "not run"  # no scanner reported for this category


@dataclass(frozen=True)
class CoverageGap:
    category: Category
    kind: GapKind
    reason: str = ""


@dataclass(frozen=True)
class Coverage:
    """Which of the four categories were assessed (a scanner ran to completion), and why not."""

    assessed: tuple[Category, ...]
    gaps: tuple[CoverageGap, ...]

    @property
    def code_analysis_assessed(self) -> bool:
        return any(c in CODE_ANALYSIS for c in self.assessed)


def coverage_of(categories: list[CategoryStatus]) -> Coverage:
    """Summarise per-scanner statuses per category, in declaration order of ``Category``.

    A category counts as assessed only when a scanner for it completed and none failed or timed
    out; ``not applicable`` alone never counts as assessed.
    """
    assessed: list[Category] = []
    gaps: list[CoverageGap] = []
    for category in Category:
        rows = [c for c in categories if c.category is category]
        broken = next((c for c in rows if c.failed), None)
        if broken is not None:
            kind = GapKind.TIMED_OUT if broken.status is ScanStatus.TIMEOUT else GapKind.FAILED
            gaps.append(CoverageGap(category, kind, broken.detail))
        elif any(c.status is ScanStatus.OK for c in rows):
            assessed.append(category)
        elif rows:
            gaps.append(CoverageGap(category, GapKind.NOT_APPLICABLE, rows[0].detail))
        else:
            gaps.append(CoverageGap(category, GapKind.NOT_RUN, "no scanner result"))
    return Coverage(tuple(assessed), tuple(gaps))


@dataclass
class PolicyOutcome:
    conclusion: Conclusion
    title: str
    decisions: list[Decision] = field(default_factory=list)
    categories: list[CategoryStatus] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    expired_waivers: list[Waiver] = field(default_factory=list)

    @property
    def coverage(self) -> Coverage:
        return coverage_of(self.categories)

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
            result.category,
            result.scanner,
            assessment,
            result.reason or "no applicable files",
            status=result.status,
        )
    if result.status is ScanStatus.OK:
        return CategoryStatus(result.category, result.scanner, assessment, status=result.status)
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
        status=result.status,
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
    return Conclusion.SUCCESS, _all_clear_title(coverage_of(categories))


def _all_clear_title(coverage: Coverage) -> str:
    """The title of a clean result. Wording only: the conclusion is already ``success``.

    "No new findings" is kept when some code-analysis category was assessed. Otherwise the title
    says what was and was not looked at, so a green check cannot be read as "the code was
    reviewed". The same rule must hold in any other implementation (see the conformance vectors).
    """
    if coverage.code_analysis_assessed:
        return "No new findings"
    if Category.SECRETS in coverage.assessed:
        return ONLY_SECRETS_TITLE
    return NOTHING_ASSESSED_TITLE
