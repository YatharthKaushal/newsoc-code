"""OSV-Scanner adapter (SCA): known-vulnerable dependencies from lockfiles.

Runs fully offline against a vulnerability database that a separate job downloads and
refreshes outside the sandbox (``newsoc refresh-osv``). ``--offline --offline-vulnerabilities``
also stops OSV-Scanner from trying deps.dev for transitive resolution, which would only
produce retries inside a no-network container.

One vulnerable dependency is one finding, however many lockfiles list it. A project that keeps
``package-lock.json`` and ``yarn.lock`` side by side would otherwise report every advisory twice.
Hits are merged when they share the project directory, the ecosystem, the package, the exact
version and the canonical advisory id (see ``_group``). The finding sits on the preferred
lockfile (``LOCKFILE_PREFERENCE``) and names the others in ``extra["also_in"]``, the message and
the evidence, so a developer knows every file that needs fixing. The fingerprint is built from the
project directory rather than the lockfile (see ``findings.fingerprint.sca_fingerprint``).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from newsoc_code import osvdb
from newsoc_code.findings.fingerprint import normalise_package, project_dir, sca_fingerprint
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
# Which file carries the finding when a project directory lists the same dependency in several
# lockfiles (lower index wins; unknown names come last, ties break on the path, so the choice
# never depends on the order of the report). It is the file a developer should edit first.
# * npm: ``npm-shrinkwrap.json`` is what npm itself reads when both it and ``package-lock.json``
#   exist; then npm's own lockfile, then yarn, then pnpm.
# * PyPI: tool-managed lockfiles before ``requirements.txt``, which is often exported from them.
LOCKFILE_PREFERENCE = (
    "npm-shrinkwrap.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "uv.lock",
    "pdm.lock",
    "pipfile.lock",
    "requirements.txt",
)
MAX_NAMED_IN_MESSAGE = 3  # other lockfiles named in the message; extra["also_in"] has them all
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

        hits: list[_Hit] = []
        for result in results:
            manifest = repo_relative(str(result.get("source", {}).get("path", "")))
            exact = result.get("source", {}).get("type") == "lockfile"
            for pkg in result.get("packages", []):
                hits += _package_hits(manifest, exact, pkg)
        findings = [self._finding(ctx, group) for group in _group(hits)]
        notes: list[str] = []
        if merged := len(hits) - len(findings):
            notes.append(
                f"{merged} repeated report(s) of the same vulnerable dependency (several "
                "lockfiles in one directory) were merged; see 'also in' on each finding"
            )
        try:
            if (status := osvdb.check(ctx.osv_db_dir)).warning:
                notes.append(status.warning)
        except osvdb.StaleDatabaseError:
            pass  # spec() refuses a stale database before running; parse tests may have no dir
        return self.ok(run, findings, notes=notes, db_snapshot=_snapshot_label(ctx))

    def _finding(self, ctx: ScanContext, group: list[_Hit]) -> Finding:
        """One finding for a dependency, on the preferred lockfile, naming the other lockfiles."""
        primary = group[0]
        name, version, ecosystem = primary.name, primary.version, primary.ecosystem
        also_in = sorted({h.manifest for h in group} - {primary.manifest})
        line = find_line_of(ctx.src_root, primary.manifest, name)
        named = [PurePosixPath(path).name for path in also_in[:MAX_NAMED_IN_MESSAGE]]
        more = len(also_in) - len(named)
        also_note = (
            f" (also in {', '.join(named)}{f' and {more} more' if more else ''})" if also_in else ""
        )
        evidence: tuple[str, ...] = (f"{name}@{version} ({ecosystem}) in {primary.manifest}",)
        if also_in:
            evidence += (f"also in: {', '.join(also_in)} (fix it in each of these files)",)
        if primary.fixed:
            evidence += (f"fixed in: {', '.join(primary.fixed[:3])}",)
        return Finding(
            source=self.name,
            category=self.category,
            rule_id=primary.canonical,
            severity=max((h.severity for h in group), key=lambda sev: sev.rank),
            confidence=Confidence.HIGH if any(h.exact for h in group) else Confidence.MEDIUM,
            path=primary.manifest,
            start_line=line,
            end_line=line,
            message=f"{name} {version} is affected by {primary.canonical}{also_note}"
            + (f": {primary.summary}" if primary.summary else ""),
            fingerprint=sca_fingerprint(
                ecosystem, name, project_dir(primary.manifest), primary.canonical
            ),
            cwe=tuple(sorted({c for h in group for c in h.cwe})),
            vuln_ids=tuple(sorted({v for h in group for v in h.all_ids})),
            evidence=evidence,
            scanner_version=self.pinned_version,
            commit=ctx.commit,
            extra={
                "package": name,
                "version": version,
                "ecosystem": ecosystem,
                "fixed_versions": list(primary.fixed),
                "max_cvss": primary.max_cvss,
                "project_dir": project_dir(primary.manifest) or ".",
                "also_in": also_in,
            },
        )


@dataclass(frozen=True)
class _Hit:
    """One advisory for one package version as listed by one lockfile, before merging."""

    manifest: str  # repository-relative path of the lockfile
    exact: bool  # the lockfile gives an exact version
    name: str
    version: str
    ecosystem: str
    canonical: str
    all_ids: tuple[str, ...]
    severity: Severity
    cwe: tuple[str, ...]
    summary: str
    fixed: tuple[str, ...]
    max_cvss: Any

    @property
    def identity(self) -> tuple[str, str, str, str, str]:
        """What makes two hits the same finding: same project directory, ecosystem, package,
        exact version and advisory. A different version, directory or ecosystem is another one."""
        return (
            project_dir(self.manifest),
            self.ecosystem.lower(),
            normalise_package(self.ecosystem, self.name),
            self.version,
            self.canonical,
        )

    @property
    def location_order(self) -> tuple[int, str]:
        """Lower sorts first and becomes the primary location (see ``LOCKFILE_PREFERENCE``)."""
        file_name = PurePosixPath(self.manifest).name.lower()
        rank = (
            LOCKFILE_PREFERENCE.index(file_name)
            if file_name in LOCKFILE_PREFERENCE
            else len(LOCKFILE_PREFERENCE)
        )
        return rank, self.manifest


def _group(hits: list[_Hit]) -> list[list[_Hit]]:
    """Hits of one dependency in one project directory, best location first in each group.

    The groups come back in a fixed order, so the result does not depend on the order in which
    osv-scanner listed its sources.
    """
    groups: dict[tuple[str, str, str, str, str], list[_Hit]] = {}
    for hit in hits:
        groups.setdefault(hit.identity, []).append(hit)
    ordered = [sorted(group, key=lambda h: h.location_order) for group in groups.values()]
    return sorted(
        ordered,
        key=lambda g: (g[0].manifest, g[0].name, g[0].version, g[0].canonical, g[0].ecosystem),
    )


def _package_hits(manifest: str, exact: bool, pkg: dict[str, Any]) -> list[_Hit]:
    info = pkg.get("package", {})
    name, version, ecosystem = (
        str(info.get("name", "")),
        str(info.get("version", "")),
        str(info.get("ecosystem", "")),
    )
    by_id = {v.get("id"): v for v in pkg.get("vulnerabilities", [])}
    out: list[_Hit] = []
    for group in pkg.get("groups", []):
        ids = [str(i) for i in group.get("ids", [])]
        all_ids = sorted(set(ids) | {str(a) for a in group.get("aliases", [])})
        canonical = next((i for i in all_ids if i.startswith("CVE-")), min(ids) if ids else "")
        vulns = [by_id[i] for i in ids if i in by_id]
        if not canonical or not vulns:
            continue
        first = vulns[0]
        summary = str(first.get("summary") or first.get("details", "")).strip().splitlines()[0:1]
        out.append(
            _Hit(
                manifest=manifest,
                exact=exact,
                name=name,
                version=version,
                ecosystem=ecosystem,
                canonical=canonical,
                all_ids=tuple(all_ids),
                severity=_severity(group, vulns, ids),
                cwe=tuple(sorted({c for v in vulns for c in _cwes(v)})),
                summary=summary[0] if summary else "",
                fixed=tuple(sorted({f for v in vulns for f in _fixed_versions(v, name)})),
                max_cvss=group.get("max_severity"),
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
