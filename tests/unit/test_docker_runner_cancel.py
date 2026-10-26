"""Timeout and cancellation of the Docker runner, using a fake ``docker`` executable.

The fake runs ``sleep`` for ``run`` and stops it for ``kill``, which exercises the real process
handling (polling, killing, exit codes) without needing a daemon.
"""

from __future__ import annotations

import stat
import threading
import time
from pathlib import Path

import pytest

from newsoc_code.runner.base import RunSpec
from newsoc_code.runner.docker import DockerRunner

FAKE_DOCKER = """#!/bin/bash
cd "$(dirname "$0")"
case "$1" in
  run)
    echo $$ > run.pid
    for arg in "$@"; do [ "$arg" = "quick" ] && exit 0; done
    exec sleep 30
    ;;
  kill)
    echo "${@:2}" >> killed.txt
    kill "$(cat run.pid)" 2>/dev/null
    ;;
  ps)
    echo abc123
    echo def456
    ;;
esac
"""


@pytest.fixture
def fake_docker(tmp_path: Path) -> Path:
    script = tmp_path / "fake-docker"
    script.write_text(FAKE_DOCKER)
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script


def runner(fake: Path, cancel: threading.Event | None = None) -> DockerRunner:
    return DockerRunner(docker_cmd=(str(fake),), cancel=cancel)


def spec(*argv: str, timeout_s: int = 30) -> RunSpec:
    return RunSpec(name="t", argv=argv or ("sleep",), timeout_s=timeout_s)


def test_a_command_that_finishes_is_returned_normally(fake_docker: Path) -> None:
    out = runner(fake_docker).run(spec("quick"))
    assert (out.exit_code, out.timed_out, out.cancelled) == (0, False, False)


def test_a_command_past_its_timeout_is_killed(fake_docker: Path) -> None:
    started = time.monotonic()
    out = runner(fake_docker).run(spec(timeout_s=1))
    assert out.timed_out and not out.cancelled
    assert time.monotonic() - started < 10
    assert (fake_docker.parent / "killed.txt").read_text().strip().startswith("newsoc-t-")


def test_setting_the_cancel_event_kills_the_container(fake_docker: Path) -> None:
    cancel = threading.Event()
    threading.Timer(0.6, cancel.set).start()
    started = time.monotonic()
    out = runner(fake_docker, cancel).run(spec(timeout_s=30))
    assert out.cancelled and not out.timed_out
    assert time.monotonic() - started < 10  # stopped long before the 30 s sleep or timeout
    assert (fake_docker.parent / "killed.txt").exists()


def test_an_already_cancelled_runner_does_not_start_anything(fake_docker: Path) -> None:
    cancel = threading.Event()
    cancel.set()
    out = runner(fake_docker, cancel).run(spec())
    assert out.cancelled and out.exit_code is None
    assert not (fake_docker.parent / "run.pid").exists()


def test_with_cancel_binds_an_event_without_mutating_the_original(fake_docker: Path) -> None:
    base = runner(fake_docker)
    event = threading.Event()
    bound = base.with_cancel(event)
    assert bound.cancel is event and base.cancel is None
    assert (bound.image, bound.docker_cmd, bound.user) == (base.image, base.docker_cmd, base.user)


def test_kill_orphans_kills_every_labelled_container(fake_docker: Path) -> None:
    assert runner(fake_docker).kill_orphans() == 2
    assert (fake_docker.parent / "killed.txt").read_text().split() == ["abc123", "def456"]
