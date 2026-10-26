"""OSV-Scanner adapter (SCA): known-vulnerable dependencies from lockfiles.

Runs fully offline against a vulnerability database that a separate job downloads and
refreshes outside the sandbox (``newsoc refresh-osv``). ``--offline --offline-vulnerabilities``
also stops OSV-Scanner from trying deps.dev for transitive resolution, which would only
produce retries inside a no-network container.
"""

from __future__ import annotations

import json
from typing import Any

from newsoc_code import osvdb
from newsoc_code.findings.fingerprint import sca_fingerprint
from newsoc_code.findings.schema import Category, Confidence, Finding, ScanResult, Severity
from newsoc_code.runner.base import Mount, RunOutput, RunSpec
from newsoc_code.scanners.base import (
    CONTAINER_OSVDB,
    CONTAINER_OUT,
    CONTAINER_SRC,
    ScanContext,
    ScannerAdapter,
    find_line_of,
    repo_relative,
)

LOCKFILES = (
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "pipfile.lock",
    "poetry.lock",
    "uv.lock",
    "pdm.lock",
)
_DB_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


class OsvAdapter(ScannerAdapter):
    name = "osv-scanner"
    category = Category.SCA
    pinned_version = "2.7.0"

    def applicable(self, ctx: ScanContext) -> str | None:
        if ctx.tree.with_name(*LOCKFILES):
            return None
        if ctx.tree.with_name("package.json"):
            return "package.json found without a lockfile, so exact versions are unknown"
        return "no supported dependency lockfile (npm or PyPI)"

    def spec(self, ctx: ScanContext) -> RunSpec:
        osvdb.check(ctx.osv_db_dir)  # raises if the database is missing or older than 7 days
        assert ctx.osv_db_dir is not None  # check() guarantees it; narrows the type
        return RunSpec(
            name="osv",
            argv=(
                "osv-scanner",
                "scan",
                "source",
                "-r",
                CONTAINER_SRC,
                "--offline",
                "--offline-vulnerabilities",
                "--format",
                "json",
                "--output-file",
                f"{CONTAINER_OUT}/osv.json",
            ),
            mounts=(
                Mount(ctx.src_root, CONTAINER_SRC, read_only=True),
                Mount(ctx.osv_db_dir, CONTAINER_OSVDB, read_only=True),
                Mount(ctx.out_dir, CONTAINER_OUT, read_only=False),
            ),
            env={"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": CONTAINER_OSVDB},
            timeout_s=300,
            memory_mb=2048,
            cpus=1.0,
        )

    def parse(self, ctx: ScanContext, run: RunOutput) -> ScanResult:
        # Exit 1 means "vulnerabilities found"; 128 with this message means no package sources.
        if run.exit_code == 128 and "No package sources found" in run.stderr_tail:
            return self.not_applicable("OSV-Scanner found no package sources")
        if (bad := self.check_run(run, ok_codes=(0, 1))) is not None:
            return bad
        try:
            data = json.loads((ctx.out_dir / "osv.json").read_text(encoding="utf-8"))
            results = data["results"]
        except (OSError, ValueError, KeyError, TypeError):
            return self.failed(run, "osv-scanner produced no readable JSON report")

        findings: list[Finding] = []
        for result in results:
            manifest = repo_relative(str(result.get("source", {}).get("path", "")))
            exact = result.get("source", {}).get("type") == "lockfile"
            for pkg in result.get("packages", []):
                findings += self._package_findings(ctx, manifest, exact, pkg)
        notes: list[str] = []
        try:
            if (status := osvdb.check(ctx.osv_db_dir)).warning:
                notes.append(status.warning)
        except osvdb.StaleDatabaseError:
            pass  # spec() refuses a stale database before running; parse tests may have no dir
        return self.ok(run, findings, notes=notes, db_snapshot=_snapshot_label(ctx))

    def _package_findings(
        self, ctx: ScanContext, manifest: str, exact: bool, pkg: dict[str, Any]
    ) -> list[Finding]:
        info = pkg.get("package", {})
        name, version, ecosystem = (
            info.get("name", ""),
            info.get("version", ""),
            info.get("ecosystem", ""),
        )
        by_id = {v.get("id"): v for v in pkg.get("vulnerabilities", [])}
        out: list[Finding] = []
        for group in pkg.get("groups", []):
            ids = [str(i) for i in group.get("ids", [])]
            all_ids = sorted(set(ids) | {str(a) for a in group.get("aliases", [])})
            canonical = next((i for i in all_ids if i.startswith("CVE-")), min(ids) if ids else "")
            vulns = [by_id[i] for i in ids if i in by_id]
            if not canonical or not vulns:
                continue
            first = vulns[0]
            fixed = sorted({f for v in vulns for f in _fixed_versions(v, name)})
            line = find_line_of(ctx.src_root, manifest, name)
            summary = (
                str(first.get("summary") or first.get("details", "")).strip().splitlines()[0:1]
            )
            out.append(
                Finding(
                    source=self.name,
                    category=self.category,
                    rule_id=canonical,
                    severity=_severity(group, vulns, ids),
                    confidence=Confidence.HIGH if exact else Confidence.MEDIUM,
                    path=manifest,
                    start_line=line,
                    end_line=line,
                    message=f"{name} {version} is affected by {canonical}"
                    + (f": {summary[0]}" if summary else ""),
                    fingerprint=sca_fingerprint(ecosystem, name, manifest, canonical),
                    cwe=tuple(sorted({c for v in vulns for c in _cwes(v)})),
                    vuln_ids=tuple(all_ids),
                    evidence=(f"{name}@{version} ({ecosystem}) in {manifest}",)
                    + ((f"fixed in: {', '.join(fixed[:3])}",) if fixed else ()),
                    scanner_version=self.pinned_version,
                    commit=ctx.commit,
                    extra={
                        "package": name,
                        "version": version,
                        "ecosystem": ecosystem,
                        "fixed_versions": fixed,
                        "max_cvss": group.get("max_severity"),
                    },
                )
            )
        return out


def _snapshot_label(ctx: ScanContext) -> str | None:
    return ctx.osv_db_dir.name if ctx.osv_db_dir else None


def _cwes(vuln: dict[str, Any]) -> list[str]:
    ids = (vuln.get("database_specific") or {}).get("cwe_ids") or []
    return [str(i).upper() for i in ids if str(i).upper().startswith("CWE-")]


def _fixed_versions(vuln: dict[str, Any], package: str) -> list[str]:
    fixed: list[str] = []
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("name", "").lower() != package.lower():
            continue
        for rng in affected.get("ranges", []):
            fixed += [str(e["fixed"]) for e in rng.get("events", []) if "fixed" in e]
    return fixed


def _severity(group: dict[str, Any], vulns: list[dict[str, Any]], ids: list[str]) -> Severity:
    if any(i.startswith("MAL-") for i in ids):
        return Severity.CRITICAL
    score: float | None
    try:
        score = float(str(group.get("max_severity")))
    except ValueError:
        score = None
    if score is not None:
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        return Severity.LOW
    for vuln in vulns:
        declared = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
        if declared in _DB_SEVERITY:
            return _DB_SEVERITY[declared]
    return Severity.MEDIUM
