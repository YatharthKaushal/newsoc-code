"""Scanner adapter interface and the helpers every adapter shares.

An adapter has three jobs: say whether the tool applies to a tree, say how to run it
(a ``RunSpec`` for a runner), and turn the tool's native output into ``Finding`` objects.
Parsing native JSON is deliberate: it is richer than SARIF. We produce SARIF ourselves from
the normalised findings (``report/sarif.py``).

The central rule: **output we cannot trust is a failure, never "zero findings"**. A crash,
timeout, kill, or unparsable report makes the category "Not assessed".
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from newsoc_code.findings.schema import Category, Finding, ScanResult, ScanStatus
from newsoc_code.runner.base import RunOutput, RunSpec

# Container paths. Adapters and the Docker runner agree on these.
CONTAINER_SRC = "/src"
CONTAINER_OUT = "/out"
CONTAINER_RULES = "/rules"
CONTAINER_OSVDB = "/osvdb"

SKIP_DIRS = frozenset(
    {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", "vendor", ".tox"}
)
MAX_TREE_FILES = 100_000
MAX_SNIPPET_FILE_BYTES = 2 * 1024 * 1024
MAX_SNIPPET_LINES = 3
MAX_SNIPPET_CHARS = 200


@dataclass
class TreeInfo:
    """A cheap index of the checkout, used to decide which scanners apply."""

    root: Path
    files: list[str] = field(default_factory=list)  # repository-relative POSIX paths
    truncated: bool = False

    @classmethod
    def scan(cls, root: Path, max_files: int = MAX_TREE_FILES) -> TreeInfo:
        info = cls(root=root)
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for name in sorted(filenames):
                full = Path(dirpath) / name
                if full.is_symlink():
                    continue
                info.files.append(full.relative_to(root).as_posix())
                if len(info.files) >= max_files:
                    info.truncated = True
                    return info
        return info

    def with_suffix(self, *suffixes: str) -> list[str]:
        return [f for f in self.files if f.lower().endswith(suffixes)]

    def with_name(self, *names: str) -> list[str]:
        wanted = {n.lower() for n in names}
        return [f for f in self.files if PurePosixPath(f).name.lower() in wanted]


@dataclass
class ScanContext:
    src_root: Path
    out_dir: Path
    tree: TreeInfo
    salt: bytes
    rules_dir: Path | None = None
    rules_version: str | None = None
    osv_db_dir: Path | None = None
    commit: str | None = None
    scope: tuple[str, ...] | None = None  # limit SAST and IaC to these files (pull request mode)
    gitleaks_mode: str = "dir"  # "dir" scans the working tree, "git" scans a commit range
    gitleaks_log_opts: str | None = None


def repo_relative(path: str) -> str:
    """Map a path reported from inside the container to a repository-relative POSIX path."""
    cleaned = path.replace("\\", "/")
    if cleaned.startswith(CONTAINER_SRC + "/"):
        cleaned = cleaned[len(CONTAINER_SRC) + 1 :]
    return cleaned.lstrip("/")


def _read_contained(root: Path, rel_path: str) -> bytes | None:
    """Read a file the scanner named: contained in ``root``, no symlinks, size-capped."""
    try:
        full = (root / rel_path).resolve()
        full.relative_to(root.resolve())
        fd = os.open(full, os.O_RDONLY | os.O_NOFOLLOW)
    except (OSError, ValueError):
        return None
    try:
        with os.fdopen(fd, "rb") as handle:
            return handle.read(MAX_SNIPPET_FILE_BYTES)
    except OSError:
        return None


def read_source_lines(root: Path, rel_path: str, start: int, end: int) -> tuple[str, ...]:
    """A few source lines for evidence.

    Semgrep CE does not return matched text without a login, so evidence is read from our own
    checkout. The path comes from a scanner that scanned hostile input, so it is not trusted.
    """
    data = _read_contained(root, rel_path)
    if data is None:
        return ()
    lines = data.decode("utf-8", errors="replace").splitlines()
    first = max(start, 1) - 1
    last = min(max(end, start), first + MAX_SNIPPET_LINES, len(lines))
    return tuple(line[:MAX_SNIPPET_CHARS] for line in lines[first:last])


def find_line_of(root: Path, rel_path: str, needle: str) -> int:
    """1-based line of the first occurrence of ``needle`` in a file, or 1 if not found."""
    data = _read_contained(root, rel_path)
    if data is None:
        return 1
    for number, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), start=1):
        if needle in line:
            return number
    return 1


def read_source_span(root: Path, rel_path: str, start_offset: int, end_offset: int) -> str | None:
    """The exact matched text (byte offsets), or None if it cannot be read safely."""
    data = _read_contained(root, rel_path)
    if data is None or not 0 <= start_offset <= end_offset <= len(data):
        return None
    return data[start_offset:end_offset].decode("utf-8", errors="replace")


class ScannerAdapter(ABC):
    name: str
    category: Category
    pinned_version: str  # must match docker/scanners.Dockerfile (a test enforces it)

    @abstractmethod
    def applicable(self, ctx: ScanContext) -> str | None:
        """Return None if the scanner applies, otherwise the reason it does not."""

    @abstractmethod
    def spec(self, ctx: ScanContext) -> RunSpec: ...

    @abstractmethod
    def parse(self, ctx: ScanContext, run: RunOutput) -> ScanResult:
        """Turn a completed run into a ScanResult. Must not raise on bad tool output."""

    # ---- helpers shared by every adapter -------------------------------------------------

    def not_applicable(self, reason: str) -> ScanResult:
        return ScanResult(
            scanner=self.name,
            category=self.category,
            status=ScanStatus.NOT_APPLICABLE,
            reason=reason,
        )

    def failed(
        self, run: RunOutput, reason: str, status: ScanStatus = ScanStatus.FAILED
    ) -> ScanResult:
        return ScanResult(
            scanner=self.name,
            category=self.category,
            status=status,
            reason=reason,
            tool_version=self.pinned_version,
            duration_ms=run.duration_ms,
            stderr_tail=run.stderr_tail,
        )

    def ok(
        self,
        run: RunOutput,
        findings: Iterable[Finding],
        notes: Iterable[str] = (),
        db_snapshot: str | None = None,
    ) -> ScanResult:
        return ScanResult(
            scanner=self.name,
            category=self.category,
            status=ScanStatus.OK,
            findings=list(findings),
            tool_version=self.pinned_version,
            duration_ms=run.duration_ms,
            stderr_tail=run.stderr_tail,
            notes=list(notes),
            db_snapshot=db_snapshot,
        )

    def check_run(self, run: RunOutput, ok_codes: tuple[int, ...]) -> ScanResult | None:
        """Common exit-status triage. Returns a failure result, or None if the run looks usable."""
        if run.timed_out:
            return self.failed(run, f"{self.name} timed out", ScanStatus.TIMEOUT)
        if run.killed:
            return self.failed(run, f"{self.name} was killed (out of memory or limit)")
        if run.exit_code not in ok_codes:
            return self.failed(run, f"{self.name} exited with status {run.exit_code}")
        return None
