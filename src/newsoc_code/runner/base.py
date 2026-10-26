"""The boundary between "what to run" (scanner adapters) and "where to run it" (sandboxes)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

STDOUT_CAP_BYTES = 256 * 1024
STDERR_TAIL_BYTES = 8 * 1024


@dataclass(frozen=True)
class Mount:
    host: Path
    container: str
    read_only: bool = True


@dataclass(frozen=True)
class RunSpec:
    """One sandboxed command. Adapters build these; runners execute them."""

    name: str
    argv: tuple[str, ...]
    mounts: tuple[Mount, ...] = ()
    env: Mapping[str, str] = field(default_factory=dict)
    timeout_s: int = 300
    memory_mb: int = 2048
    cpus: float = 2.0
    pids: int = 256


@dataclass
class RunOutput:
    exit_code: int | None
    stdout: str = ""
    stderr_tail: str = ""
    timed_out: bool = False
    duration_ms: int = 0
    cancelled: bool = False  # stopped on request (the job was superseded)

    @property
    def killed(self) -> bool:
        """128+9: the kernel or Docker killed the process (out of memory is the usual cause)."""
        return self.exit_code == 137


class Runner(Protocol):
    def run(self, spec: RunSpec) -> RunOutput: ...
