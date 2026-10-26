"""Small builders for findings and scan results used across the unit tests."""

from __future__ import annotations

import itertools

from newsoc_code.findings.schema import (
    Category,
    Confidence,
    Finding,
    ScanResult,
    ScanStatus,
    Severity,
)

_counter = itertools.count(1)


def finding(
    *,
    category: Category = Category.SAST,
    severity: Severity = Severity.HIGH,
    confidence: Confidence = Confidence.HIGH,
    rule_id: str = "newsoc.js.exec-concat",
    path: str = "src/app.js",
    fingerprint: str | None = None,
    cwe: tuple[str, ...] = ("CWE-78",),
    vuln_ids: tuple[str, ...] = (),
) -> Finding:
    n = next(_counter)
    return Finding(
        source="test",
        category=category,
        rule_id=rule_id,
        severity=severity,
        confidence=confidence,
        path=path,
        start_line=1,
        end_line=1,
        message="test finding",
        fingerprint=fingerprint or f"fp-{n}",
        cwe=cwe,
        vuln_ids=vuln_ids,
    )


def result(
    category: Category = Category.SAST,
    findings: list[Finding] | None = None,
    status: ScanStatus = ScanStatus.OK,
    reason: str | None = None,
) -> ScanResult:
    return ScanResult(
        scanner=f"{category.value}-scanner",
        category=category,
        status=status,
        findings=findings or [],
        reason=reason,
    )
