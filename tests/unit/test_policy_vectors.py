"""Run the shared conformance vectors against the Python policy engine."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from newsoc_code.findings.schema import (
    Category,
    Confidence,
    Finding,
    ScanResult,
    ScanStatus,
    Severity,
)
from newsoc_code.policy.engine import evaluate
from newsoc_code.policy.loader import load_policy

VECTORS = sorted((Path(__file__).parents[2] / "contracts" / "vectors" / "policy").glob("*.json"))


def _finding(raw: dict) -> Finding:
    return Finding(
        source="vector",
        category=Category(raw["category"]),
        rule_id=raw["rule_id"],
        severity=Severity(raw["severity"]),
        confidence=Confidence(raw["confidence"]),
        path=raw["path"],
        start_line=1,
        end_line=1,
        message="vector",
        fingerprint=raw["fingerprint"],
        cwe=tuple(raw["cwe"]),
        vuln_ids=tuple(raw["vuln_ids"]),
    )


def _result(raw: dict) -> ScanResult:
    return ScanResult(
        scanner=raw["scanner"],
        category=Category(raw["category"]),
        status=ScanStatus(raw["status"]),
        reason=raw["reason"],
        findings=[_finding(f) for f in raw["findings"]],
    )


def test_the_vectors_exist():
    assert len(VECTORS) >= 15


@pytest.mark.parametrize("path", VECTORS, ids=[p.stem for p in VECTORS])
def test_vector(path: Path):
    case = json.loads(path.read_text())
    today = date.fromisoformat(case["today"])
    baseline = None if case["baseline"] is None else frozenset(case["baseline"])

    out = evaluate(
        load_policy(case["policy_yaml"], today),
        [_result(r) for r in case["results"]],
        baseline,
        today,
    )

    expected = case["expected"]
    assert out.conclusion.value == expected["conclusion"], case["description"]
    assert out.title == expected["title"]
    assert {d.finding.fingerprint: d.outcome.value for d in out.decisions} == expected["outcomes"]
