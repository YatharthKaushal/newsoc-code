"""The ``.secpolicy.yml`` model (MVP subset of plan.md section 3.4).

Supported in the MVP: ``version``, ``profile``, ``mode``, ``gates.merge``, ``actions``,
``on_scanner_error`` and ``waivers``. Other keys from the long-term design (``deploy``,
``auto_fix``, ``compliance``, ``notify``) are accepted with a warning and ignored.
"""

from __future__ import annotations

from datetime import date
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from newsoc_code.findings.schema import Category, Severity

MAX_WAIVER_DAYS = 365


class Mode(StrEnum):
    OBSERVE = "observe"  # report and comment, never block
    ENFORCE = "enforce"  # blocking findings fail the check


class Action(StrEnum):
    WARN = "warn"
    BLOCK = "block"


class Waiver(BaseModel):
    """Accepts one rule (rule id, CWE, CVE or GHSA) for matching paths until ``expires``."""

    model_config = ConfigDict(frozen=True)

    rule: str
    path: str = "**"
    expires: date
    approved_by: str
    reason: str | None = None


class MergeGate(BaseModel):
    model_config = ConfigDict(frozen=True)

    block_on: tuple[Severity, ...] = (Severity.CRITICAL, Severity.HIGH)
    new_findings_only: bool = True


class Policy(BaseModel):
    model_config = ConfigDict(frozen=True)

    version: int = 1
    profile: str = "standard"
    mode: Mode = Mode.OBSERVE
    merge: MergeGate = Field(default_factory=MergeGate)
    actions: dict[str, Action] = Field(
        default_factory=lambda: {
            "default": Action.WARN,
            "secrets": Action.BLOCK,
            "sca": Action.BLOCK,
            "sast": Action.BLOCK,
            "iac": Action.WARN,
        }
    )
    on_scanner_error: Action = Action.WARN
    waivers: tuple[Waiver, ...] = ()

    def action_for(self, category: Category) -> Action:
        return self.actions.get(category.value, self.actions.get("default", Action.WARN))
