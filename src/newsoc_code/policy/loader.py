"""Parse ``.secpolicy.yml`` text into a ``Policy`` without ever raising on bad input.

Missing policy  -> built-in defaults in *observe* mode, with a notice.
Invalid policy  -> built-in defaults in *enforce* mode, flagged invalid. Breaking the file must
                   never silently open the gate, so an invalid file fails closed.
The caller supplies the text read from the **base branch**, never from a pull request head.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Any

import yaml
from pydantic import ValidationError

from newsoc_code.findings.schema import Category, Severity
from newsoc_code.policy.schema import (
    MAX_WAIVER_DAYS,
    Action,
    MergeGate,
    Mode,
    Policy,
    Waiver,
)

MAX_POLICY_BYTES = 64 * 1024
SUPPORTED_KEYS = {"version", "profile", "mode", "gates", "actions", "on_scanner_error", "waivers"}
DEFERRED_KEYS = {"deploy", "auto_fix", "compliance", "notify"}  # long-term design, not in the MVP
CATEGORY_KEYS = {c.value for c in Category} | {"default"}
DEFERRED_ACTIONS = {"suggest-fix", "auto-fix-pr"}  # treated as warn in the MVP


@dataclass
class PolicyLoad:
    policy: Policy
    source: str  # "file" | "defaults"
    invalid: bool = False
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def title_note(self) -> str | None:
        if self.invalid:
            return "Policy invalid; built-in strict defaults applied"
        if self.source == "defaults":
            return "No .secpolicy.yml found; built-in defaults applied (observe mode)"
        return None


def _invalid(errors: list[str], warnings: list[str] | None = None) -> PolicyLoad:
    return PolicyLoad(
        policy=Policy(mode=Mode.ENFORCE),
        source="defaults",
        invalid=True,
        errors=errors,
        warnings=warnings or [],
    )


def load_policy(text: str | None, today: date) -> PolicyLoad:
    if text is None:
        return PolicyLoad(policy=Policy(), source="defaults")
    if len(text.encode("utf-8")) > MAX_POLICY_BYTES:
        return _invalid([f"policy file is larger than {MAX_POLICY_BYTES // 1024} KB"])
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        first_line = str(exc).strip().splitlines()[0] if str(exc).strip() else "invalid YAML"
        return _invalid([f"policy is not valid YAML: {first_line}"])
    if raw is None:
        return PolicyLoad(policy=Policy(), source="defaults", warnings=["policy file is empty"])
    if not isinstance(raw, dict):
        return _invalid(["policy must be a YAML mapping"])

    errors: list[str] = []
    warnings: list[str] = []
    version = raw.get("version", 1)
    if version != 1:
        return _invalid([f"unsupported policy version {version!r} (this build supports 1)"])

    for key in raw:
        if key in DEFERRED_KEYS:
            warnings.append(f"'{key}' is not supported in this version and was ignored")
        elif key not in SUPPORTED_KEYS:
            warnings.append(f"unknown key '{key}' was ignored")

    mode = _enum(Mode, raw.get("mode", "observe"), "mode", errors)
    on_error = _action(raw.get("on_scanner_error", "warn"), "on_scanner_error", errors, warnings)
    merge = _merge_gate(raw.get("gates"), errors, warnings)
    actions = _actions(raw.get("actions"), errors, warnings)
    waivers = _waivers(raw.get("waivers"), today, errors)
    profile = str(raw.get("profile", "standard"))

    if errors:
        return _invalid(errors, warnings)
    try:
        policy = Policy(
            profile=profile,
            mode=mode,
            merge=merge,
            actions=actions,
            on_scanner_error=on_error,
            waivers=tuple(waivers),
        )
    except ValidationError as exc:  # defensive: individual checks above should have caught it
        return _invalid([e["msg"] for e in exc.errors()], warnings)
    return PolicyLoad(policy=policy, source="file", warnings=warnings)


# ---- section parsers ------------------------------------------------------------------------


def _enum(enum_cls: Any, value: Any, name: str, errors: list[str]) -> Any:
    try:
        return enum_cls(str(value).lower())
    except ValueError:
        allowed = ", ".join(m.value for m in enum_cls)
        errors.append(f"{name} must be one of: {allowed} (got {value!r})")
        return next(iter(enum_cls))


def _action(value: Any, name: str, errors: list[str], warnings: list[str]) -> Action:
    text = str(value).lower()
    if text in DEFERRED_ACTIONS:
        warnings.append(f"{name}: '{text}' is not available yet and is treated as 'warn'")
        return Action.WARN
    return _enum(Action, text, name, errors)  # type: ignore[no-any-return]


def _merge_gate(gates: Any, errors: list[str], warnings: list[str]) -> MergeGate:
    if gates is None:
        return MergeGate()
    if not isinstance(gates, dict):
        errors.append("gates must be a mapping")
        return MergeGate()
    for key in gates:
        if key != "merge":
            warnings.append(f"gates.{key} is not supported in this version and was ignored")
    merge = gates.get("merge") or {}
    if not isinstance(merge, dict):
        errors.append("gates.merge must be a mapping")
        return MergeGate()
    severities: list[Severity] = []
    for item in merge.get("block_on", [s.value for s in MergeGate().block_on]):
        try:
            severities.append(Severity(str(item).lower()))
        except ValueError:
            errors.append(f"gates.merge.block_on has an unknown severity {item!r}")
    flag = merge.get("new_findings_only", True)
    if not isinstance(flag, bool):
        errors.append("gates.merge.new_findings_only must be true or false")
        flag = True
    return MergeGate(block_on=tuple(dict.fromkeys(severities)), new_findings_only=flag)


def _actions(raw: Any, errors: list[str], warnings: list[str]) -> dict[str, Action]:
    result = dict(Policy().actions)
    if raw is None:
        return result
    if not isinstance(raw, dict):
        errors.append("actions must be a mapping")
        return result
    for key, value in raw.items():
        if key not in CATEGORY_KEYS:
            warnings.append(f"actions.{key} is not a known category and was ignored")
            continue
        result[key] = _action(value, f"actions.{key}", errors, warnings)
    return result


def _waivers(raw: Any, today: date, errors: list[str]) -> list[Waiver]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        errors.append("waivers must be a list")
        return []
    out: list[Waiver] = []
    for index, item in enumerate(raw, start=1):
        label = f"waivers[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{label} must be a mapping")
            continue
        expires = item.get("expires")
        if isinstance(expires, str):
            try:
                expires = date.fromisoformat(expires)
            except ValueError:
                errors.append(f"{label}.expires is not a date (use YYYY-MM-DD)")
                continue
        if not isinstance(expires, date):
            errors.append(f"{label} needs an 'expires' date: waivers must expire")
            continue
        if expires > today + timedelta(days=MAX_WAIVER_DAYS):
            errors.append(f"{label}.expires is more than {MAX_WAIVER_DAYS} days away")
            continue
        if not item.get("rule") or not item.get("approved_by"):
            errors.append(f"{label} needs 'rule' and 'approved_by'")
            continue
        try:
            out.append(
                Waiver(
                    rule=str(item["rule"]),
                    path=str(item.get("path", "**")),
                    expires=expires,
                    approved_by=str(item["approved_by"]),
                    reason=str(item["reason"]) if item.get("reason") else None,
                )
            )
        except ValidationError as exc:
            errors.append(f"{label}: {exc.errors()[0]['msg']}")
    return out
