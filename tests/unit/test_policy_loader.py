from __future__ import annotations

from datetime import date, timedelta

import pytest

from newsoc_code.findings.schema import Category, Severity
from newsoc_code.policy.loader import MAX_POLICY_BYTES, load_policy
from newsoc_code.policy.schema import Action, Mode

TODAY = date(2026, 10, 26)

PLAN_EXAMPLE = """
version: 1
profile: standard
gates:
  merge:
    block_on: [critical, high]
    new_findings_only: true
  deploy:
    block_on: [critical]
    require_checks: [secrets, sca]
actions:
  default: suggest-fix
  secrets: block
  dependency_malicious: block
  iac: suggest-fix
auto_fix:
  enabled: true
waivers:
  - rule: CWE-79
    path: legacy/**
    expires: 2027-03-31
    approved_by: security-lead
compliance:
  frameworks: [asvs-4.0.3]
notify:
  channels: [slack:#sec-alerts]
"""


def test_missing_policy_gives_observe_mode_defaults():
    load = load_policy(None, TODAY)
    assert not load.invalid and load.source == "defaults"
    assert load.policy.mode is Mode.OBSERVE
    assert load.policy.action_for(Category.SECRETS) is Action.BLOCK
    assert load.policy.action_for(Category.IAC) is Action.WARN
    assert load.title_note and "No .secpolicy.yml" in load.title_note


def test_plan_example_loads_with_warnings_for_deferred_features():
    load = load_policy(PLAN_EXAMPLE, TODAY)
    assert not load.invalid, load.errors
    text = " ".join(load.warnings)
    for deferred in ("deploy", "auto_fix", "compliance", "notify"):
        assert deferred in text
    assert "dependency_malicious" in text  # not a category: ignored with a warning
    assert load.policy.action_for(Category.IAC) is Action.WARN  # suggest-fix treated as warn
    assert load.policy.waivers[0].expires == date(2027, 3, 31)


def test_enforce_mode_and_custom_block_levels():
    load = load_policy(
        "mode: enforce\ngates:\n  merge:\n    block_on: [critical]\n    new_findings_only: false\n",
        TODAY,
    )
    assert not load.invalid
    assert load.policy.mode is Mode.ENFORCE
    assert load.policy.merge.block_on == (Severity.CRITICAL,)
    assert load.policy.merge.new_findings_only is False


@pytest.mark.parametrize(
    ("text", "fragment"),
    [
        ("version: 2\n", "unsupported policy version"),
        ("::: not yaml :::\n  - [", "not valid YAML"),
        ("- just\n- a list\n", "must be a YAML mapping"),
        ("mode: yolo\n", "mode must be one of"),
        ("gates:\n  merge:\n    block_on: [catastrophic]\n", "unknown severity"),
        ("on_scanner_error: explode\n", "on_scanner_error must be one of"),
        ("waivers:\n  - rule: CWE-79\n    approved_by: me\n", "waivers must expire"),
        ("waivers:\n  - rule: CWE-79\n    expires: 2026-12-31\n", "needs 'rule' and 'approved_by'"),
        (
            "waivers:\n  - rule: CWE-79\n    approved_by: me\n    expires: not-a-date\n",
            "not a date",
        ),
        ("waivers: nope\n", "waivers must be a list"),
    ],
)
def test_invalid_policies_fail_closed(text, fragment):
    load = load_policy(text, TODAY)
    assert load.invalid
    assert any(fragment in e for e in load.errors), load.errors
    assert load.policy.mode is Mode.ENFORCE  # breaking the file must never open the gate
    assert load.title_note and "invalid" in load.title_note


def test_a_waiver_more_than_a_year_out_is_invalid():
    far = TODAY + timedelta(days=366)
    load = load_policy(
        f"waivers:\n  - rule: CWE-79\n    approved_by: me\n    expires: {far}\n", TODAY
    )
    assert load.invalid and "more than 365 days" in load.errors[0]
    near = TODAY + timedelta(days=365)
    assert not load_policy(
        f"waivers:\n  - rule: CWE-79\n    approved_by: me\n    expires: {near}\n", TODAY
    ).invalid


def test_an_already_expired_waiver_still_loads():
    load = load_policy(
        "waivers:\n  - rule: CWE-79\n    approved_by: me\n    expires: 2020-01-01\n", TODAY
    )
    assert not load.invalid and len(load.policy.waivers) == 1


def test_oversized_policy_is_rejected():
    load = load_policy("# " + "x" * MAX_POLICY_BYTES, TODAY)
    assert load.invalid and "larger than" in load.errors[0]


def test_yaml_tags_cannot_construct_objects():
    load = load_policy("mode: !!python/object/apply:os.system ['echo pwned']\n", TODAY)
    assert load.invalid  # safe_load refuses python tags


def test_empty_file_is_treated_as_defaults():
    load = load_policy("", TODAY)
    assert not load.invalid and load.warnings == ["policy file is empty"]
