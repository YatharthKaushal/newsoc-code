"""Guard the sandbox: the flags that make a scan safe must not be dropped by accident."""

from __future__ import annotations

from pathlib import Path

from newsoc_code.runner.base import Mount, RunSpec
from newsoc_code.runner.docker import DockerRunner


def _cmd(**kw) -> list[str]:
    spec = RunSpec(
        name="t",
        argv=("semgrep", "--version"),
        mounts=(
            Mount(Path("/tmp"), "/src", read_only=True),
            Mount(Path("/tmp"), "/out", read_only=False),
        ),
        env={"A": "1"},
        **kw,
    )
    return DockerRunner(user="1000:1000").build_command(spec, "newsoc-t-abc")


def _pair(cmd: list[str], flag: str) -> str:
    return cmd[cmd.index(flag) + 1]


def test_no_network_read_only_no_capabilities():
    cmd = _cmd()
    assert _pair(cmd, "--network") == "none"
    assert "--read-only" in cmd
    assert _pair(cmd, "--cap-drop") == "ALL"
    assert _pair(cmd, "--security-opt") == "no-new-privileges"


def test_runs_as_a_non_root_user():
    cmd = _cmd()
    user = _pair(cmd, "--user")
    assert user not in ("0", "0:0", "root", "root:root")


def test_resource_limits_are_set():
    cmd = _cmd(memory_mb=1024, cpus=1.5, pids=64)
    assert _pair(cmd, "--memory") == "1024m"
    assert _pair(cmd, "--memory-swap") == "1024m"  # no swap
    assert _pair(cmd, "--cpus") == "1.5"
    assert _pair(cmd, "--pids-limit") == "64"


def test_source_is_mounted_read_only_and_output_read_write():
    cmd = _cmd()
    mounts = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-v"]
    assert any(m.endswith(":/src:ro") for m in mounts)
    assert any(m.endswith(":/out:rw") for m in mounts)


def test_environment_is_explicit_and_command_follows_the_image():
    cmd = _cmd()
    assert cmd[cmd.index("-e") + 1] == "A=1"  # only what the adapter asked for
    assert "--env-file" not in cmd
    assert cmd[-3:] == [
        "newsoc/scanners:dev",
        "semgrep",
        "--version",
    ]  # image, then the tool and args
