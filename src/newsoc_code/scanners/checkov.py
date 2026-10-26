"""Checkov adapter (infrastructure as code: Terraform and Dockerfiles).

Open-source Checkov reports no severity, so we keep a curated table; unlisted checks default
to medium. The default policy only warns on ``iac``, so an uncurated check cannot block a merge
unless a repository opts in.
"""

from __future__ import annotations

import json
from typing import Any

from newsoc_code.findings.fingerprint import iac_fingerprint
from newsoc_code.findings.schema import Category, Confidence, Finding, ScanResult, Severity
from newsoc_code.runner.base import Mount, RunOutput, RunSpec
from newsoc_code.scanners.base import (
    CONTAINER_OUT,
    CONTAINER_SRC,
    ScanContext,
    ScannerAdapter,
    read_source_lines,
    repo_relative,
)

C, H, M, L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW
# Curated severities. Extend as checks are reviewed; see tests/unit/test_checkov_adapter.py.
SEVERITY: dict[str, Severity] = {
    # Secrets and credentials in code
    "CKV_AWS_41": C,
    "CKV_AWS_46": C,
    "CKV_AWS_45": C,
    "CKV_SECRET_2": C,
    # Public exposure
    "CKV_AWS_57": C,
    "CKV_AWS_20": H,
    "CKV_AWS_17": H,
    "CKV_AWS_24": H,
    "CKV_AWS_25": H,
    "CKV_AWS_260": M,
    "CKV_AWS_277": H,
    "CKV2_AWS_6": H,
    "CKV_AWS_53": H,
    "CKV_AWS_54": H,
    "CKV_AWS_55": M,
    "CKV_AWS_56": M,
    "CKV_AWS_93": H,
    "CKV_AWS_69": H,
    # Encryption at rest and in transit
    "CKV_AWS_16": H,
    "CKV_AWS_3": H,
    "CKV_AWS_19": M,
    "CKV_AWS_27": M,
    "CKV_AWS_8": M,
    "CKV_AWS_2": M,
    "CKV_AWS_103": M,
    "CKV_AWS_34": M,
    "CKV_AWS_35": M,
    # Identity and access
    "CKV_AWS_1": H,
    "CKV_AWS_49": H,
    "CKV_AWS_33": H,
    "CKV_AWS_40": L,
    "CKV_AWS_79": M,
    "CKV_AWS_109": H,
    "CKV_AWS_110": H,
    "CKV_AWS_111": M,
    # Hygiene (logging, versioning, resilience): real, but rarely urgent
    "CKV_AWS_18": L,
    "CKV_AWS_21": L,
    "CKV_AWS_145": L,
    "CKV_AWS_23": L,
    "CKV_AWS_36": L,
    "CKV_AWS_67": L,
    "CKV_AWS_7": L,
    "CKV_AWS_28": L,
    "CKV_AWS_226": L,
    "CKV_AWS_157": L,
    "CKV_AWS_161": L,
    "CKV_AWS_118": L,
    "CKV_AWS_129": L,
    "CKV_AWS_293": L,
    "CKV_AWS_51": M,
    # Dockerfile
    "CKV_DOCKER_1": H,
    "CKV_DOCKER_8": H,
    "CKV_DOCKER_3": M,
    "CKV_DOCKER_7": M,
    "CKV_DOCKER_2": L,
    "CKV_DOCKER_4": L,
    "CKV_DOCKER_5": L,
    "CKV_DOCKER_9": L,
    "CKV_DOCKER_10": L,
    "CKV_DOCKER_11": L,
}
DEFAULT_SEVERITY = M
FRAMEWORKS = ("terraform", "dockerfile")


def _is_iac(path: str) -> bool:
    name = path.rsplit("/", 1)[-1].lower()
    return (
        path.lower().endswith((".tf", ".tf.json"))
        or name.startswith("dockerfile")
        or name.endswith(".dockerfile")
    )


class CheckovAdapter(ScannerAdapter):
    name = "checkov"
    category = Category.IAC
    pinned_version = "3.3.30"

    def applicable(self, ctx: ScanContext) -> str | None:
        files = [f for f in ctx.tree.files if _is_iac(f)]
        if ctx.scope is not None:
            files = [f for f in files if f in set(ctx.scope)]
        return None if files else "no Terraform or Dockerfile changes to analyse"

    def spec(self, ctx: ScanContext) -> RunSpec:
        return RunSpec(
            name="checkov",
            argv=(
                "checkov",
                "-d",
                CONTAINER_SRC,
                "--framework",
                *FRAMEWORKS,
                "--skip-download",
                "--download-external-modules",
                "false",
                "--soft-fail",
                "-o",
                "json",
                "--output-file-path",
                CONTAINER_OUT,
                "--quiet",
            ),
            mounts=(
                Mount(ctx.src_root, CONTAINER_SRC, read_only=True),
                Mount(ctx.out_dir, CONTAINER_OUT, read_only=False),
            ),
            env={"BC_SKIP_MAPPING": "TRUE", "CHECKOV_NO_UPDATE_CHECK": "1"},
            timeout_s=300,
            memory_mb=1536,
            cpus=1.0,
        )

    def parse(self, ctx: ScanContext, run: RunOutput) -> ScanResult:
        if (bad := self.check_run(run, ok_codes=(0,))) is not None:
            return bad
        try:
            data = json.loads((ctx.out_dir / "results_json.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return self.failed(run, "checkov produced no readable JSON report")
        documents = data if isinstance(data, list) else [data]  # one document per framework

        findings: list[Finding] = []
        notes: list[str] = []
        for doc in documents:
            if not isinstance(doc, dict) or "results" not in doc:
                continue
            parsing_errors = (doc.get("summary") or {}).get("parsing_errors", 0)
            if parsing_errors:
                notes.append(
                    f"checkov could not parse {parsing_errors} {doc.get('check_type')} file(s)"
                )
            for check in doc["results"].get("failed_checks", []):
                finding = self._finding(ctx, check)
                if finding is not None:
                    findings.append(finding)
        return self.ok(run, findings, notes)

    def _finding(self, ctx: ScanContext, check: dict[str, Any]) -> Finding | None:
        try:
            check_id = str(check["check_id"])
            path = repo_relative(str(check["file_path"]))
            start, end = (int(n) for n in check["file_line_range"][:2])
        except (KeyError, TypeError, ValueError):
            return None
        resource = str(check.get("resource") or "")
        curated = check_id in SEVERITY
        return Finding(
            source=self.name,
            category=self.category,
            rule_id=check_id,
            severity=SEVERITY.get(check_id, DEFAULT_SEVERITY),
            confidence=Confidence.HIGH if curated else Confidence.MEDIUM,
            path=path,
            start_line=max(start, 1),
            end_line=max(end, start, 1),
            message=str(check.get("check_name") or check_id),
            fingerprint=iac_fingerprint(check_id, path, resource),
            evidence=(f"resource {resource}",)
            if resource
            else read_source_lines(ctx.src_root, path, start, end),
            scanner_version=self.pinned_version,
            commit=ctx.commit,
            extra={
                "resource": resource,
                "guideline": check.get("guideline"),
                "curated_severity": curated,
            },
        )
