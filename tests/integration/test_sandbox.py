"""The sandbox guarantees, checked against a real container."""

from __future__ import annotations

import subprocess
import time

import pytest

from newsoc_code.runner.base import RunSpec
from newsoc_code.runner.docker import DockerRunner
from newsoc_code.scanners.checkov import CheckovAdapter
from newsoc_code.scanners.gitleaks import GitleaksAdapter
from newsoc_code.scanners.osv import OsvAdapter
from newsoc_code.scanners.semgrep import SemgrepAdapter

pytestmark = pytest.mark.docker


@pytest.fixture(scope="module")
def runner() -> DockerRunner:
    return DockerRunner()


def _run(runner: DockerRunner, *argv: str, **kw):
    return runner.run(RunSpec(name="itest", argv=argv, **kw))


def test_network_is_unreachable(runner):
    out = _run(
        runner, "python3", "-c", "import socket; socket.create_connection(('1.1.1.1', 443), 3)"
    )
    assert out.exit_code != 0
    assert "unreachable" in out.stderr_tail.lower()


def test_root_filesystem_is_read_only(runner):
    out = _run(runner, "sh", "-c", "touch /opt/should-fail")
    assert out.exit_code != 0
    assert "read-only" in out.stderr_tail.lower()


def test_runs_as_non_root(runner):
    out = _run(runner, "id", "-u")
    assert out.exit_code == 0
    assert out.stdout.strip() != "0"


def test_capabilities_are_dropped(runner):
    out = _run(runner, "sh", "-c", "grep CapEff /proc/self/status")
    assert out.stdout.split()[-1].strip("0") == ""  # effective capability mask is all zeros


def test_timeout_kills_the_container_promptly(runner):
    started = time.monotonic()
    out = _run(runner, "sleep", "60", timeout_s=3)
    assert out.timed_out
    assert time.monotonic() - started < 30
    leftover = subprocess.run(
        [*runner.docker_cmd, "ps", "-q", "--filter", "label=newsoc.managed=true"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert leftover.stdout.strip() == "", "a timed-out scan must not leave a container running"


def test_memory_limit_kills_a_greedy_process(runner):
    out = _run(
        runner, "python3", "-c", "x = bytearray(600 * 1024 * 1024); print(len(x))", memory_mb=128
    )
    assert out.killed or out.exit_code not in (0, None)


@pytest.mark.parametrize(
    ("tool", "adapter", "needle"),
    [
        (("semgrep", "--version"), SemgrepAdapter, "1.182.1"),
        (("checkov", "--version"), CheckovAdapter, "3.3.30"),
        (("osv-scanner", "--version"), OsvAdapter, "2.7.0"),
        (("gitleaks", "version"), GitleaksAdapter, "8.30.1"),
    ],
    ids=["semgrep", "checkov", "osv", "gitleaks"],
)
def test_image_contains_the_pinned_tool_versions(runner, tool, adapter, needle):
    out = _run(runner, *tool)
    assert out.exit_code == 0
    assert needle in out.stdout
    assert adapter.pinned_version == needle
