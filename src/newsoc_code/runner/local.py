"""Run a command directly on the host with NO sandbox.

Only for unit tests that need a fake scanner (a shell script that writes a canned report).
Never wire this into the worker: scanning hostile repositories requires the Docker runner.
"""

from __future__ import annotations

import subprocess
import time

from newsoc_code.runner.base import STDERR_TAIL_BYTES, STDOUT_CAP_BYTES, RunOutput, RunSpec


class LocalRunner:
    def run(self, spec: RunSpec) -> RunOutput:
        started = time.monotonic()
        try:
            done = subprocess.run(  # noqa: S603
                list(spec.argv),
                capture_output=True,
                check=False,
                timeout=spec.timeout_s,
                env=dict(spec.env) or None,
            )
        except subprocess.TimeoutExpired as exc:
            return RunOutput(
                exit_code=None,
                stdout=(exc.stdout or b"")[:STDOUT_CAP_BYTES].decode("utf-8", "replace"),
                stderr_tail=(exc.stderr or b"")[-STDERR_TAIL_BYTES:].decode("utf-8", "replace"),
                timed_out=True,
                duration_ms=int((time.monotonic() - started) * 1000),
            )
        return RunOutput(
            exit_code=done.returncode,
            stdout=done.stdout[:STDOUT_CAP_BYTES].decode("utf-8", "replace"),
            stderr_tail=done.stderr[-STDERR_TAIL_BYTES:].decode("utf-8", "replace"),
            duration_ms=int((time.monotonic() - started) * 1000),
        )
