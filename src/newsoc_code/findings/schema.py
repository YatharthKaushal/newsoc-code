"""The finding model shared by every scanner adapter, the policy engine and the reporters.

This is the Code arm's half of the cross-arm finding schema (see plan.md section 2). The JSON
Schema generated from these models lives in ``contracts/`` so another language can validate
against it.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1}[self.value]


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {"high": 3, "medium": 2, "low": 1}[self.value]


class Category(StrEnum):
    SAST = "sast"
    SCA = "sca"
    SECRETS = "secrets"
    IAC = "iac"


class AssessmentStatus(StrEnum):
    """Per-finding and per-category status words; never "compliant" or "secure"."""

    FINDING = "Finding"
    VERIFIED = "Verified"  # scanner X ran with no findings at commit Y
    MANUAL_EVIDENCE = "Manual evidence required"
    NOT_ASSESSED = "Not assessed"


class ScanStatus(StrEnum):
    OK = "ok"
    FAILED = "failed"
    TIMEOUT = "timeout"
    NOT_APPLICABLE = "not_applicable"


class Finding(BaseModel):
    """One normalised result from any scanner."""

    model_config = ConfigDict(frozen=True)

    source: str = Field(description="Scanner that produced the finding, e.g. semgrep")
    category: Category
    rule_id: str
    severity: Severity
    confidence: Confidence
    path: str = Field(description="Repository-relative POSIX path")
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    message: str
    fingerprint: str = Field(description="Stable across line shifts; used for dedupe and baselines")
    cwe: tuple[str, ...] = ()
    vuln_ids: tuple[str, ...] = ()
    evidence: tuple[str, ...] = Field(
        default=(), description="Up to a few redacted source lines or a one-line description"
    )
    control_refs: tuple[str, ...] = Field(default=(), description="Empty in the MVP")
    status: AssessmentStatus = AssessmentStatus.FINDING
    action_taken: str = "none"
    rule_version: str | None = None
    scanner_version: str | None = None
    commit: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    """What one scanner run produced, including when it produced nothing usable."""

    scanner: str
    category: Category
    status: ScanStatus
    findings: list[Finding] = Field(default_factory=list)
    tool_version: str | None = None
    reason: str | None = Field(default=None, description="Why a run was skipped or failed")
    duration_ms: int = 0
    stderr_tail: str = ""
    notes: list[str] = Field(default_factory=list)
    db_snapshot: str | None = None

    @property
    def assessed(self) -> bool:
        """True when the category can be reported as assessed (including 'no findings')."""
        return self.status is ScanStatus.OK

    def assessment(self) -> AssessmentStatus:
        if self.status is not ScanStatus.OK:
            return AssessmentStatus.NOT_ASSESSED
        return AssessmentStatus.FINDING if self.findings else AssessmentStatus.VERIFIED
