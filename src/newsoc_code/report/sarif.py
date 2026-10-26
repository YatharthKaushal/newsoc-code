"""SARIF 2.1.0 export of normalised findings.

SARIF is exported, not uploaded: uploading to GitHub code scanning needs ``security_events:
write`` and, on private repositories, GitHub Advanced Security. The file is an artifact a
customer can load into their own tooling.
"""

from __future__ import annotations

from typing import Any

from newsoc_code import __version__
from newsoc_code.findings.schema import Finding, ScanResult, ScanStatus, Severity
from newsoc_code.policy.engine import Decision, Outcome

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}
# GitHub orders code-scanning alerts by this 0-10 score.
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
}


def to_sarif(
    results: list[ScanResult],
    decisions: list[Decision] | None = None,
    baseline_known: bool = False,
) -> dict[str, Any]:
    findings = [f for r in results for f in r.findings]
    by_fp = {d.finding.fingerprint: d for d in decisions or []}
    rules, rule_index = _rules(findings)

    sarif_results = [
        _result(f, rule_index[f.rule_id], by_fp.get(f.fingerprint), baseline_known)
        for f in sorted(findings, key=lambda x: (x.path, x.start_line, x.rule_id, x.fingerprint))
    ]
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "newsoc",
                        "version": __version__,
                        "informationUri": "https://example.invalid/newsoc",
                        "rules": rules,
                    }
                },
                "invocations": [_invocation(results)],
                "results": sarif_results,
            }
        ],
    }


def _rules(findings: list[Finding]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    first: dict[str, Finding] = {}
    for f in sorted(findings, key=lambda x: x.rule_id):
        first.setdefault(f.rule_id, f)
    rules, index = [], {}
    for i, (rule_id, f) in enumerate(first.items()):
        index[rule_id] = i
        rules.append(
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": f.message[:200]},
                "properties": {
                    "category": f.category.value,
                    "scanner": f.source,
                    "security-severity": SECURITY_SEVERITY[f.severity],
                    "tags": ["security", f.category.value, *f.cwe],
                },
            }
        )
    return rules, index


def _result(
    f: Finding, rule_idx: int, decision: Decision | None, baseline_known: bool
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": f.rule_id,
        "ruleIndex": rule_idx,
        "level": LEVEL[f.severity],
        "message": {"text": f.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f.path, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": f.start_line, "endLine": f.end_line},
                }
            }
        ],
        "partialFingerprints": {"newsoc/v1": f.fingerprint},
        "properties": {
            "severity": f.severity.value,
            "confidence": f.confidence.value,
            "category": f.category.value,
            "status": f.status.value,
            "cwe": list(f.cwe),
            "vulnerabilityIds": list(f.vuln_ids),
            "evidence": list(f.evidence),
        },
    }
    if baseline_known:
        unchanged = decision is not None and decision.outcome is Outcome.BASELINED
        result["baselineState"] = "unchanged" if unchanged else "new"
    if decision is not None:
        result["properties"]["outcome"] = decision.outcome.value
        if decision.outcome is Outcome.WAIVED and decision.waiver is not None:
            result["suppressions"] = [
                {
                    "kind": "external",
                    "status": "accepted",
                    "justification": (
                        f"Waived by {decision.waiver.approved_by} until {decision.waiver.expires}"
                    ),
                }
            ]
    return result


def _invocation(results: list[ScanResult]) -> dict[str, Any]:
    notifications = []
    for r in results:
        if r.status in (ScanStatus.FAILED, ScanStatus.TIMEOUT):
            level, text = "error", f"{r.scanner}: Not assessed ({r.reason or r.status.value})"
        elif r.status is ScanStatus.NOT_APPLICABLE:
            level, text = "note", f"{r.scanner}: Not assessed ({r.reason or 'no applicable files'})"
        else:
            level, text = "none", f"{r.scanner}: {r.assessment().value}"
        notifications.append({"level": level, "message": {"text": text}})
    clean = all(r.status in (ScanStatus.OK, ScanStatus.NOT_APPLICABLE) for r in results)
    return {"executionSuccessful": clean, "toolExecutionNotifications": notifications}
