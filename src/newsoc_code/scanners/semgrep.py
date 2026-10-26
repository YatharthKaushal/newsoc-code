"""Semgrep CE adapter (SAST).

We run only our own rule pack, mounted at /rules. Registry rules are never used: the Semgrep
Rules License v1.0 forbids them in a product that is sold (see docs/MVP_PLAN.md).
Semgrep CE returns "requires login" instead of the matched text, so evidence and the
fingerprint come from reading the match span out of our own checkout.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from typing import Any

from newsoc_code.findings.fingerprint import sast_fingerprint
from newsoc_code.findings.schema import Category, Confidence, Finding, ScanResult, Severity
from newsoc_code.runner.base import Mount, RunOutput, RunSpec
from newsoc_code.scanners.base import (
    CONTAINER_OUT,
    CONTAINER_RULES,
    CONTAINER_SRC,
    ScanContext,
    ScannerAdapter,
    read_source_lines,
    read_source_span,
    repo_relative,
)

SOURCE_SUFFIXES = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py")
EXCLUDES = (
    # build output and third-party code
    "node_modules",
    "dist",
    "build",
    "vendor",
    "*.min.js",
    "migrations",
    # tests and fixtures
    "tests",
    "test",
    "__tests__",
    "fixtures",
    "*.test.*",
    "*.spec.*",
    # documentation, samples and benchmarks: real code, but demonstration rather than product
    "docs",
    "doc",
    "examples",
    "example",
    "sandbox",
    "benchmarks",
    "benchmark",
)
MAX_SCOPED_FILES = 500
# Error types in Semgrep's JSON `errors` array that mean a file was analysed incompletely.
PARTIAL_PARSE_ERROR = "PartialParsing"
SYNTAX_ERRORS = frozenset(
    {"SyntaxError", "LexicalError", "ParseError", "OtherParseError", "AstBuilderError"}
)
MAX_NOTE_PATHS = 5
MAX_NOTE_PATH_CHARS = 120
_CWE = re.compile(r"CWE-\d+", re.IGNORECASE)
_SEVERITY_BY_LEVEL = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}


class SemgrepAdapter(ScannerAdapter):
    name = "semgrep"
    category = Category.SAST
    pinned_version = "1.182.1"

    def applicable(self, ctx: ScanContext) -> str | None:
        files = ctx.tree.with_suffix(*SOURCE_SUFFIXES)
        if ctx.scope is not None:
            files = [f for f in files if f in set(ctx.scope)]
        return None if files else "no JavaScript, TypeScript or Python files to analyse"

    def spec(self, ctx: ScanContext) -> RunSpec:
        if ctx.rules_dir is None:
            raise ValueError("semgrep needs our rule pack: ScanContext.rules_dir is not set")
        argv = [
            "semgrep",
            "scan",
            "--config",
            CONTAINER_RULES,
            "--metrics=off",
            "--disable-version-check",
            "--quiet",
            "--json",
            "--output",
            f"{CONTAINER_OUT}/semgrep.json",
            "--jobs",
            "2",
            "--max-memory",
            "2500",
            "--timeout",
            "30",
        ]
        for pattern in EXCLUDES:
            argv += ["--exclude", pattern]
        targets = [CONTAINER_SRC]
        if ctx.scope is not None:
            scoped = [f for f in ctx.scope if f.lower().endswith(SOURCE_SUFFIXES)]
            if 0 < len(scoped) <= MAX_SCOPED_FILES:
                targets = [f"{CONTAINER_SRC}/{f}" for f in scoped]
        return RunSpec(
            name="semgrep",
            argv=(*argv, *targets),
            mounts=(
                Mount(ctx.src_root, CONTAINER_SRC, read_only=True),
                Mount(ctx.rules_dir, CONTAINER_RULES, read_only=True),
                Mount(ctx.out_dir, CONTAINER_OUT, read_only=False),
            ),
            timeout_s=300,
            memory_mb=2560,
            cpus=2.0,
        )

    def parse(self, ctx: ScanContext, run: RunOutput) -> ScanResult:
        if (bad := self.check_run(run, ok_codes=(0,))) is not None:
            return bad
        report = ctx.out_dir / "semgrep.json"
        try:
            data = json.loads(report.read_text(encoding="utf-8"))
            results = data["results"]
        except (OSError, ValueError, KeyError, TypeError):
            return self.failed(run, "semgrep produced no readable JSON report")

        findings: list[Finding] = []
        seen: dict[tuple[str, str, str], int] = defaultdict(int)
        for item in results:
            finding = self._finding(ctx, item, seen)
            if finding is not None:
                findings.append(finding)

        return self.ok(run, findings, _error_notes(data.get("errors")))

    def _finding(
        self, ctx: ScanContext, item: dict[str, Any], seen: dict[tuple[str, str, str], int]
    ) -> Finding | None:
        try:
            path = repo_relative(item["path"])
            start, end = item["start"], item["end"]
            extra = item.get("extra", {})
            meta = extra.get("metadata", {}) or {}
            rule_id = _rule_id(item["check_id"])
        except (KeyError, TypeError):
            return None

        match_text = read_source_span(
            ctx.src_root, path, start.get("offset", -1), end.get("offset", -1)
        )
        if match_text is None:
            match_text = " ".join(read_source_lines(ctx.src_root, path, start["line"], end["line"]))
        key = (rule_id, path, " ".join(match_text.split()))
        occurrence = seen[key]
        seen[key] += 1

        cwe = tuple(
            dict.fromkeys(
                m.upper() for c in _as_list(meta.get("cwe")) for m in _CWE.findall(str(c))
            )
        )
        return Finding(
            source=self.name,
            category=self.category,
            rule_id=rule_id,
            severity=_severity(meta, str(extra.get("severity", ""))),
            confidence=_confidence(meta),
            path=path,
            start_line=max(int(start["line"]), 1),
            end_line=max(int(end["line"]), int(start["line"]), 1),
            message=str(extra.get("message", rule_id)),
            fingerprint=sast_fingerprint(rule_id, path, match_text, occurrence),
            cwe=cwe,
            evidence=read_source_lines(ctx.src_root, path, int(start["line"]), int(end["line"])),
            rule_version=ctx.rules_version,
            scanner_version=self.pinned_version,
            commit=ctx.commit,
            extra={"references": _as_list(meta.get("references"))},
        )


def _error_type(error: dict[str, Any]) -> str:
    """Semgrep writes the type as ``"SyntaxError"`` or as ``["PartialParsing", [locations]]``."""
    kind = error.get("type")
    if isinstance(kind, (list, tuple)):
        kind = kind[0] if kind else ""
    return kind if isinstance(kind, str) else ""


def _error_path(error: dict[str, Any]) -> str:
    path = error.get("path")
    if not isinstance(path, str) or not path:
        spans = error.get("spans")
        first = spans[0] if isinstance(spans, list) and spans else None
        path = first.get("file") if isinstance(first, dict) else None
    return repo_relative(path) if isinstance(path, str) and path else "(unknown file)"


def _listed(paths: list[str]) -> str:
    shown = ", ".join(p[:MAX_NOTE_PATH_CHARS] for p in paths[:MAX_NOTE_PATHS])
    more = len(paths) - MAX_NOTE_PATHS
    return f"{shown} (+{more} more)" if more > 0 else shown


def _error_notes(errors: Any) -> list[str]:
    """Turn Semgrep's ``errors`` array into notes a developer can act on.

    A file Semgrep could only partly parse (``PartialParsing``) or not parse at all is analysed
    incompletely, so a clean result for it proves less than it seems to. Paths are distinct and
    repository-relative; the container's /src prefix is stripped like everywhere else.
    """
    if not isinstance(errors, list):
        return []
    partial: set[str] = set()
    unparsed: set[str] = set()
    other = 0
    for error in errors:
        if not isinstance(error, dict):
            other += 1
            continue
        kind = _error_type(error)
        if kind == PARTIAL_PARSE_ERROR:
            partial.add(_error_path(error))
        elif kind in SYNTAX_ERRORS:
            unparsed.add(_error_path(error))
        else:
            other += 1

    notes = []
    if unparsed:
        notes.append(
            f"{len(unparsed)} file(s) could not be parsed, so they were not analysed: "
            f"{_listed(sorted(unparsed))}"
        )
    partial -= unparsed  # the worse state wins
    if partial:
        notes.append(
            f"{len(partial)} file(s) were only partly parsed, so findings in them may be "
            f"missing: {_listed(sorted(partial))}"
        )
    if other:
        notes.append(f"semgrep reported {other} other non-fatal error(s)")
    return notes


def _rule_id(check_id: str) -> str:
    """Semgrep prefixes ids with the config path; our rules all start with ``newsoc.``."""
    idx = check_id.find("newsoc.")
    return check_id[idx:] if idx >= 0 else check_id


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _severity(meta: dict[str, Any], level: str) -> Severity:
    declared = str(meta.get("severity", "")).lower()
    if declared in {s.value for s in Severity}:
        return Severity(declared)
    return _SEVERITY_BY_LEVEL.get(level.upper(), Severity.MEDIUM)


def _confidence(meta: dict[str, Any]) -> Confidence:
    declared = str(meta.get("confidence", "")).lower()
    return Confidence(declared) if declared in {c.value for c in Confidence} else Confidence.MEDIUM
