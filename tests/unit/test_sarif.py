from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest
from jsonschema import Draft4Validator

from newsoc_code.findings.schema import Category, ScanStatus, Severity
from newsoc_code.policy.engine import evaluate
from newsoc_code.policy.loader import load_policy
from newsoc_code.report.sarif import to_sarif
from tests.factories import finding, result

SCHEMA = json.loads(
    (Path(__file__).parents[1] / "fixtures" / "schemas" / "sarif-schema-2.1.0.json").read_text()
)
TODAY = date(2026, 10, 26)


def validate(doc: dict) -> None:
    Draft4Validator(SCHEMA).validate(doc)


@pytest.fixture
def mixed_results():
    return [
        result(
            Category.SAST,
            [
                finding(severity=Severity.HIGH, path="src/b.js"),
                finding(severity=Severity.LOW, path="src/a.js", rule_id="newsoc.js.other"),
            ],
        ),
        result(
            Category.SECRETS,
            [
                finding(
                    category=Category.SECRETS,
                    severity=Severity.CRITICAL,
                    rule_id="github-pat",
                    cwe=("CWE-798",),
                    path="cfg.js",
                )
            ],
        ),
        result(Category.IAC, status=ScanStatus.NOT_APPLICABLE, reason="no Terraform files"),
        result(Category.SCA, status=ScanStatus.FAILED, reason="database missing"),
    ]


def test_output_validates_against_the_official_sarif_schema(mixed_results):
    validate(to_sarif(mixed_results))


def test_empty_scan_is_valid_sarif():
    validate(to_sarif([result(Category.SAST), result(Category.SECRETS)]))


def test_levels_and_security_severity_follow_our_severity(mixed_results):
    doc = to_sarif(mixed_results)
    run = doc["runs"][0]
    levels = {r["ruleId"]: r["level"] for r in run["results"]}
    assert levels["github-pat"] == "error" and levels["newsoc.js.other"] == "note"
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    assert rules["github-pat"]["properties"]["security-severity"] == "9.5"
    assert "CWE-798" in rules["github-pat"]["properties"]["tags"]


def test_rule_index_points_at_the_matching_rule(mixed_results):
    run = to_sarif(mixed_results)["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    for r in run["results"]:
        assert rules[r["ruleIndex"]]["id"] == r["ruleId"]


def test_results_are_sorted_so_output_is_deterministic(mixed_results):
    doc = to_sarif(mixed_results)
    paths = [
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for r in doc["runs"][0]["results"]
    ]
    assert paths == sorted(paths)
    assert json.dumps(to_sarif(mixed_results), sort_keys=True) == json.dumps(
        to_sarif(list(mixed_results)), sort_keys=True
    )


def test_failed_and_skipped_scanners_are_reported_as_not_assessed(mixed_results):
    inv = to_sarif(mixed_results)["runs"][0]["invocations"][0]
    texts = [n["message"]["text"] for n in inv["toolExecutionNotifications"]]
    assert any("Not assessed" in t and "database missing" in t for t in texts)
    assert any("no Terraform files" in t for t in texts)
    assert inv["executionSuccessful"] is False  # a scanner failed


def test_clean_scan_reports_verified_per_scanner():
    inv = to_sarif([result(Category.SAST)])["runs"][0]["invocations"][0]
    assert inv["executionSuccessful"] is True
    assert inv["toolExecutionNotifications"][0]["message"]["text"].endswith("Verified")


def test_waived_findings_carry_a_suppression_and_baselined_ones_are_unchanged():
    waived = finding(rule_id="newsoc.js.exec-concat", cwe=("CWE-78",))
    existing = finding(rule_id="newsoc.js.eval", cwe=("CWE-95",))
    fresh = finding(rule_id="newsoc.js.sql", cwe=("CWE-89",))
    policy = (
        "mode: enforce\nwaivers:\n  - rule: newsoc.js.exec-concat\n"
        "    expires: 2026-12-31\n    approved_by: sec-lead\n"
    )
    results = [result(findings=[waived, existing, fresh])]
    out = evaluate(load_policy(policy, TODAY), results, frozenset({existing.fingerprint}), TODAY)

    doc = to_sarif(results, out.decisions, baseline_known=True)
    validate(doc)
    by_rule = {r["ruleId"]: r for r in doc["runs"][0]["results"]}
    assert (
        by_rule["newsoc.js.exec-concat"]["suppressions"][0]["justification"]
        == "Waived by sec-lead until 2026-12-31"
    )
    assert by_rule["newsoc.js.eval"]["baselineState"] == "unchanged"
    assert by_rule["newsoc.js.sql"]["baselineState"] == "new"
    assert by_rule["newsoc.js.sql"]["properties"]["outcome"] == "blocked"


def test_fingerprint_is_exported_for_cross_run_matching():
    f = finding(fingerprint="abc123")
    doc = to_sarif([result(findings=[f])])
    assert doc["runs"][0]["results"][0]["partialFingerprints"] == {"newsoc/v1": "abc123"}
