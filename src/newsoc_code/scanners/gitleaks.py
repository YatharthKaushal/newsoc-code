"""Gitleaks adapter (secrets).

Secret values are handled carefully:
* The report is read unredacted (so we can derive a stable fingerprint) and deleted as soon
  as it is parsed.
* Only a keyed hash of the value is kept, never the value.
* Evidence shows the line with the secret replaced by [REDACTED]; at most the first four
  characters of a long secret are kept to help the owner locate and rotate it.
"""

from __future__ import annotations

import json
from collections import defaultdict
from fnmatch import fnmatchcase
from pathlib import PurePosixPath
from typing import Any

from newsoc_code.findings.fingerprint import secret_hash, secrets_fingerprint
from newsoc_code.findings.schema import Category, Confidence, Finding, ScanResult, Severity
from newsoc_code.runner.base import Mount, RunOutput, RunSpec
from newsoc_code.scanners.base import (
    CONTAINER_OUT,
    CONTAINER_SRC,
    ScanContext,
    ScannerAdapter,
    repo_relative,
)

CRITICAL_RULES = frozenset(
    {
        "private-key",
        "aws-access-token",
        "github-pat",
        "github-fine-grained-pat",
        "github-oauth",
        "github-app-token",
        "gitlab-pat",
        "stripe-access-token",
        "gcp-api-key",
        "azure-ad-client-secret",
        "slack-bot-token",
        "slack-user-token",
        "npm-access-token",
        "pypi-upload-token",
    }
)
MEDIUM_CONFIDENCE_RULES = frozenset({"generic-api-key"})
MIN_PREFIX_SECRET_LEN = 20

# Dependency lock and checksum manifests (matched case-insensitively on the file name, at any
# depth). Their "name: <hash>" lines look like credentials to Gitleaks' entropy-based rule, e.g.
# the SPEC CHECKSUMS section of a CocoaPods Podfile.lock.
CHECKSUM_MANIFEST_PATTERNS = (
    "*.lock",  # Podfile.lock, yarn.lock, Cargo.lock, Gemfile.lock, poetry.lock, composer.lock, ...
    "*.sum",  # go.sum, go.work.sum
    "*.lockfile",  # gradle.lockfile
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "packages.lock.json",  # NuGet
    "package.resolved",  # Swift Package Manager
    ".terraform.lock.hcl",
)
# Only these rules are dropped for those files. Specific rules (github-pat, aws-access-token,
# private-key, ...) match a fixed token shape, so a hit in a lock file is still a real leak.
CHECKSUM_NOISY_RULES = frozenset({"generic-api-key"})
MAX_SUPPRESSED_FILES_LISTED = 3


class GitleaksAdapter(ScannerAdapter):
    name = "gitleaks"
    category = Category.SECRETS
    pinned_version = "8.30.1"

    def applicable(self, ctx: ScanContext) -> str | None:
        return None if ctx.tree.files else "empty repository"

    def spec(self, ctx: ScanContext) -> RunSpec:
        common = [
            "--report-format",
            "json",
            "--report-path",
            f"{CONTAINER_OUT}/gitleaks.json",
            "--no-banner",
            "--no-color",
            "--max-target-megabytes",
            "5",
        ]
        if ctx.gitleaks_mode == "git":
            argv = [
                "gitleaks",
                "git",
                CONTAINER_SRC,
                *common,
                f"--log-opts={ctx.gitleaks_log_opts or '--all'}",
            ]
        else:
            argv = ["gitleaks", "dir", CONTAINER_SRC, *common]
        return RunSpec(
            name="gitleaks",
            argv=tuple(argv),
            mounts=(
                Mount(ctx.src_root, CONTAINER_SRC, read_only=True),
                Mount(ctx.out_dir, CONTAINER_OUT, read_only=False),
            ),
            env={
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "safe.directory",
                "GIT_CONFIG_VALUE_0": "*",
            },
            timeout_s=300,
            memory_mb=768,
            cpus=1.0,
        )

    def parse(self, ctx: ScanContext, run: RunOutput) -> ScanResult:
        report = ctx.out_dir / "gitleaks.json"
        try:
            # Exit 1 means "leaks found".
            if (bad := self.check_run(run, ok_codes=(0, 1))) is not None:
                return bad
            try:
                raw = report.read_text(encoding="utf-8") if report.exists() else "[]"
                leaks = json.loads(raw or "[]")
                if not isinstance(leaks, list):
                    raise ValueError("report is not a list")
            except (OSError, ValueError):
                return self.failed(run, "gitleaks produced no readable JSON report")
            if run.exit_code == 1 and not leaks:
                return self.failed(run, "gitleaks reported leaks but wrote no report")
            # Dropped before grouping, so a value that also appears in real source still counts.
            kept, dropped = _drop_checksum_noise(leaks)
            notes = [_suppression_note(dropped)] if dropped else []
            return self.ok(run, self._findings(ctx, kept), notes)
        finally:
            report.unlink(missing_ok=True)  # it holds raw secret values

    def _findings(self, ctx: ScanContext, leaks: list[dict[str, Any]]) -> list[Finding]:
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        fingerprints: dict[str, str] = {}
        for leak in leaks:
            rule_id = str(leak.get("RuleID", "unknown"))
            value = str(leak.get("Secret") or leak.get("Match") or "")
            fp = secrets_fingerprint(rule_id, secret_hash(value, ctx.salt))
            grouped[fp].append(leak)
            fingerprints[fp] = rule_id

        findings: list[Finding] = []
        for fp, group in grouped.items():
            first, rest = group[0], group[1:]
            rule_id = fingerprints[fp]
            secret = str(first.get("Secret") or "")
            start = max(int(first.get("StartLine", 1)), 1)
            findings.append(
                Finding(
                    source=self.name,
                    category=self.category,
                    rule_id=rule_id,
                    severity=Severity.CRITICAL if rule_id in CRITICAL_RULES else Severity.HIGH,
                    confidence=Confidence.MEDIUM
                    if rule_id in MEDIUM_CONFIDENCE_RULES
                    else Confidence.HIGH,
                    path=repo_relative(str(first.get("File", ""))),
                    start_line=start,
                    end_line=max(int(first.get("EndLine", start)), start),
                    message=str(first.get("Description") or f"Possible secret ({rule_id})"),
                    fingerprint=fp,
                    cwe=("CWE-798",),
                    evidence=(_masked(first, secret),),
                    scanner_version=self.pinned_version,
                    commit=str(first.get("Commit") or "") or ctx.commit,
                    extra={
                        "secret_prefix": secret[:4]
                        if len(secret) >= MIN_PREFIX_SECRET_LEN
                        else None,
                        "history_commit": first.get("Commit") or None,
                        "other_locations": [
                            {
                                "path": repo_relative(str(x.get("File", ""))),
                                "line": x.get("StartLine"),
                            }
                            for x in rest
                        ],
                    },
                )
            )
        return findings


def is_checksum_manifest(path: str) -> bool:
    """True for a lock or checksum manifest, judged by file name only."""
    name = PurePosixPath(repo_relative(path)).name.lower()
    return any(fnmatchcase(name, pattern) for pattern in CHECKSUM_MANIFEST_PATTERNS)


def _drop_checksum_noise(
    leaks: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split off entropy-rule hits inside lock and checksum manifests.

    This applies the same way to a working-tree scan and to a history scan: history records
    carry the path the file had in that commit, and a lock file is as noisy there as now.
    """
    kept: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []
    for leak in leaks:
        rule_id, file = str(leak.get("RuleID", "")), str(leak.get("File", ""))
        noisy = rule_id in CHECKSUM_NOISY_RULES and is_checksum_manifest(file)
        (dropped if noisy else kept).append(leak)
    return kept, dropped


def _suppression_note(dropped: list[dict[str, Any]]) -> str:
    files = sorted({repo_relative(str(leak.get("File", ""))) for leak in dropped})
    shown = ", ".join(files[:MAX_SUPPRESSED_FILES_LISTED])
    if len(files) > MAX_SUPPRESSED_FILES_LISTED:
        shown += f" (+{len(files) - MAX_SUPPRESSED_FILES_LISTED} more)"
    return (
        f"gitleaks ignored {len(dropped)} generic-api-key match(es) in lock or checksum "
        f"file(s) ({shown}), which hold dependency hashes. Specific secret rules still apply "
        "to those files."
    )


def _masked(leak: dict[str, Any], secret: str) -> str:
    line = str(leak.get("Match") or "")
    if secret:
        line = line.replace(secret, "[REDACTED]")
    return " ".join(line.split())[:200]
