"""Scanner stand-ins that read the real checked-out files, so pipeline tests need no Docker.

``MarkerSast`` reports a high-severity finding for every line containing ``VULN(``. Its
fingerprint ignores line numbers (like the real ones), so moving a line does not make it new.
"""

from __future__ import annotations

import hashlib
import threading
from pathlib import Path

from newsoc_code.findings.schema import (
    Category,
    Confidence,
    Finding,
    ScanResult,
    Severity,
)
from newsoc_code.runner.base import RunOutput, RunSpec
from newsoc_code.scanners.base import ScanContext, ScannerAdapter


class FakeRunner:
    """Pretends to run a container: returns immediately, or notices cancellation."""

    def __init__(self, cancel: threading.Event | None = None) -> None:
        self.cancel = cancel
        self.specs: list[RunSpec] = []

    def run(self, spec: RunSpec) -> RunOutput:
        self.specs.append(spec)
        if self.cancel is not None and self.cancel.is_set():
            return RunOutput(exit_code=None, cancelled=True)
        return RunOutput(exit_code=0, duration_ms=3)


class BlockingRunner(FakeRunner):
    """Blocks inside ``run`` until cancelled (or released), like a long scan."""

    def __init__(self, cancel: threading.Event | None = None) -> None:
        super().__init__(cancel)
        self.started = threading.Event()
        self.release = threading.Event()

    def run(self, spec: RunSpec) -> RunOutput:
        self.started.set()
        while not self.release.is_set():
            if self.cancel is not None and self.cancel.wait(0.05):
                return RunOutput(exit_code=None, cancelled=True)
        return RunOutput(exit_code=0, duration_ms=3)


class MarkerSast(ScannerAdapter):
    name = "marker-sast"
    category = Category.SAST
    pinned_version = "0.0.1"

    def __init__(self) -> None:
        self.contexts: list[ScanContext] = []

    def _files(self, ctx: ScanContext) -> list[str]:
        files = [f for f in ctx.tree.files if f.endswith((".js", ".py"))]
        if ctx.scope is not None:
            files = [f for f in files if f in set(ctx.scope)]
        return files

    def applicable(self, ctx: ScanContext) -> str | None:
        return None if self._files(ctx) else "no source files to analyse"

    def spec(self, ctx: ScanContext) -> RunSpec:
        return RunSpec(name="marker-sast", argv=("true",))

    def parse(self, ctx: ScanContext, run: RunOutput) -> ScanResult:
        self.contexts.append(ctx)
        if run.cancelled or run.exit_code != 0:
            return self.failed(run, "stopped")
        findings = []
        for rel in self._files(ctx):
            text = Path(ctx.src_root, rel).read_text(errors="replace")
            for number, line in enumerate(text.splitlines(), start=1):
                if "VULN(" not in line:
                    continue
                digest = hashlib.sha256(f"{rel}:{line.strip()}".encode()).hexdigest()[:32]
                findings.append(
                    Finding(
                        source=self.name,
                        category=self.category,
                        rule_id="fake.marker-vuln",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        path=rel,
                        start_line=number,
                        end_line=number,
                        message="marker vulnerability",
                        fingerprint=digest,
                        commit=ctx.commit,
                        cwe=("CWE-78",),
                    )
                )
        return self.ok(run, findings)


class CrashingScanner(ScannerAdapter):
    """Always reports that the tool crashed (a Not assessed category)."""

    name = "marker-secrets"
    category = Category.SECRETS
    pinned_version = "0.0.1"

    def applicable(self, ctx: ScanContext) -> str | None:
        return None

    def spec(self, ctx: ScanContext) -> RunSpec:
        return RunSpec(name="crash", argv=("true",))

    def parse(self, ctx: ScanContext, run: RunOutput) -> ScanResult:
        return self.failed(
            RunOutput(exit_code=2, stderr_tail="boom"), "marker-secrets exited with status 2"
        )
