"""Run scanners in a locked-down container.

Every run gets: no network, a read-only root filesystem, no capabilities, no privilege
escalation, a non-root user, and memory, CPU and process limits. The source tree is mounted
read-only; the only writable places are a small tmpfs and an output directory the adapter
asked for. Credentials never enter a container: the worker clones the repository itself.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import threading
import time
import uuid
from collections.abc import Sequence
from typing import IO

from newsoc_code.runner.base import (
    STDERR_TAIL_BYTES,
    STDOUT_CAP_BYTES,
    RunOutput,
    RunSpec,
)

_KILL_GRACE_S = 15
_POLL_S = 0.25
MANAGED_LABEL = "newsoc.managed=true"


class DockerRunner:
    def __init__(
        self,
        image: str = "newsoc/scanners:dev",
        docker_cmd: Sequence[str] = ("docker",),
        user: str | None = None,
        tmpfs_mb: int = 512,
        cancel: threading.Event | None = None,
    ) -> None:
        self.image = image
        self.docker_cmd = tuple(docker_cmd)
        self.user = user or f"{os.getuid()}:{os.getgid()}"
        self.tmpfs_mb = tmpfs_mb
        self.cancel = cancel

    def with_cancel(self, cancel: threading.Event) -> DockerRunner:
        """A runner for one job: setting ``cancel`` kills whatever container it is running."""
        return DockerRunner(self.image, self.docker_cmd, self.user, self.tmpfs_mb, cancel)

    def build_command(self, spec: RunSpec, container_name: str) -> list[str]:
        cmd = [
            *self.docker_cmd,
            "run",
            "--rm",
            "--init",
            "--name",
            container_name,
            "--label",
            MANAGED_LABEL,
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(spec.pids),
            "--memory",
            f"{spec.memory_mb}m",
            "--memory-swap",
            f"{spec.memory_mb}m",
            "--cpus",
            str(spec.cpus),
            "--ulimit",
            "nofile=4096:4096",
            "--ulimit",
            "core=0",
            "--user",
            self.user,
            "--tmpfs",
            f"/tmp:rw,size={self.tmpfs_mb}m,mode=1777",  # noqa: S108
        ]
        for mount in spec.mounts:
            flag = "ro" if mount.read_only else "rw"
            cmd += ["-v", f"{mount.host.resolve()}:{mount.container}:{flag}"]
        for key, value in spec.env.items():
            cmd += ["-e", f"{key}={value}"]
        cmd += [self.image, *spec.argv]
        return cmd

    def _kill(self, container_name: str) -> None:
        subprocess.run(  # noqa: S603
            [*self.docker_cmd, "kill", container_name],
            capture_output=True,
            check=False,
            timeout=_KILL_GRACE_S,
        )

    def run(self, spec: RunSpec) -> RunOutput:
        if self.cancel is not None and self.cancel.is_set():
            return RunOutput(exit_code=None, cancelled=True)
        name = f"newsoc-{spec.name}-{uuid.uuid4().hex[:8]}"
        cmd = self.build_command(spec, name)
        started = time.monotonic()
        deadline = started + spec.timeout_s
        timed_out = cancelled = False
        # Output goes to temporary files, not pipes, so a noisy scanner cannot exhaust memory.
        with tempfile.TemporaryFile() as out_f, tempfile.TemporaryFile() as err_f:
            proc = subprocess.Popen(cmd, stdout=out_f, stderr=err_f, start_new_session=True)  # noqa: S603
            exit_code: int | None = None
            while True:
                try:
                    exit_code = proc.wait(timeout=_POLL_S)
                    break
                except subprocess.TimeoutExpired:
                    pass
                if self.cancel is not None and self.cancel.is_set():
                    cancelled = True
                elif time.monotonic() >= deadline:
                    timed_out = True
                else:
                    continue
                self._kill(name)
                try:
                    exit_code = proc.wait(timeout=_KILL_GRACE_S)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    exit_code = None
                break
            stdout = _read_head(out_f, STDOUT_CAP_BYTES)
            stderr_tail = _read_tail(err_f, STDERR_TAIL_BYTES)
        return RunOutput(
            exit_code=exit_code,
            stdout=stdout,
            stderr_tail=stderr_tail,
            timed_out=timed_out,
            duration_ms=int((time.monotonic() - started) * 1000),
            cancelled=cancelled,
        )

    def kill_orphans(self) -> int:
        """Kill containers a previous worker left behind (it crashed or was restarted)."""
        try:
            listed = subprocess.run(  # noqa: S603
                [*self.docker_cmd, "ps", "-q", "--filter", f"label={MANAGED_LABEL}"],
                capture_output=True,
                text=True,
                check=False,
                timeout=_KILL_GRACE_S,
            )
            ids = listed.stdout.split()
            if ids:
                subprocess.run(  # noqa: S603
                    [*self.docker_cmd, "kill", *ids],
                    capture_output=True,
                    check=False,
                    timeout=_KILL_GRACE_S,
                )
            return len(ids)
        except (OSError, subprocess.TimeoutExpired):
            return 0

    def available(self) -> bool:
        """True if the Docker daemon is reachable and our image exists."""
        try:
            probe = subprocess.run(  # noqa: S603
                [*self.docker_cmd, "image", "inspect", self.image],
                capture_output=True,
                check=False,
                timeout=20,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return probe.returncode == 0


def _read_head(f: IO[bytes], cap: int) -> str:
    f.seek(0)
    return f.read(cap).decode("utf-8", errors="replace")


def _read_tail(f: IO[bytes], cap: int) -> str:
    f.seek(0, os.SEEK_END)
    size = f.tell()
    f.seek(max(0, size - cap))
    return f.read().decode("utf-8", errors="replace")
