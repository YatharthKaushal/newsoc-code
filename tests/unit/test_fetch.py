"""The git layer against real local repositories (file:// remotes), plus a recording git wrapper."""

from __future__ import annotations

import base64
import os
import stat
from pathlib import Path

import pytest
from gitremote import Remote, git

from newsoc_code.github.fetch import (
    CheckoutTooLarge,
    GitError,
    StaleHead,
    Workspace,
    valid_fetch_target,
    valid_repo,
    valid_sha,
)

TOKEN = "ghs_FAKE_installation_token_0123456789"
# Every git call carries `-c key=value` options (some contain the word "fetch"), so a wrapper
# script must look at the first argument that is not part of a `-c` pair.
SUBCOMMAND = (
    'args=("$@"); i=0; while [ "${args[$i]}" = "-c" ]; do i=$((i+2)); done; sub="${args[$i]}"\n'
)


@pytest.fixture
def remote(tmp_path: Path) -> Remote:
    return Remote(tmp_path / "remote")


def workspace(tmp_path: Path, remote: Remote, **kw: object) -> Workspace:
    kw.setdefault("allow_file_protocol", True)
    ws = Workspace(tmp_path / "job", remote.url, **kw)  # type: ignore[arg-type]
    ws.init()
    return ws


def test_fetch_and_checkout_a_commit(tmp_path: Path, remote: Remote) -> None:
    sha = remote.commit({"src/app.py": "print(1)\n"})
    ws = workspace(tmp_path, remote)
    assert ws.fetch(sha, depth=1, name="head") == sha
    root = ws.checkout(sha)
    assert (root / "src" / "app.py").read_text() == "print(1)\n"
    assert git(root, "rev-parse", "HEAD") == sha


def test_fetch_a_pull_request_head_ref(tmp_path: Path, remote: Remote) -> None:
    remote.commit({"a.txt": "1"})
    pr_sha = remote.commit({"b.txt": "2"})
    remote.pull_ref(7, pr_sha)
    git(remote.bare, "update-ref", "-d", "refs/heads/main")  # reachable only through the PR ref
    ws = workspace(tmp_path, remote)
    assert ws.fetch("refs/pull/7/head", depth=1, name="head", expect_sha=pr_sha) == pr_sha


def test_a_pull_request_that_moved_is_reported_as_stale(tmp_path: Path, remote: Remote) -> None:
    old = remote.commit({"a.txt": "1"})
    new = remote.commit({"a.txt": "2"})
    remote.pull_ref(7, new)
    ws = workspace(tmp_path, remote)
    with pytest.raises(StaleHead):
        ws.fetch("refs/pull/7/head", depth=1, name="head", expect_sha=old)


def test_history_depth_is_bounded(tmp_path: Path, remote: Remote) -> None:
    shas = [remote.commit({"f.txt": str(n)}, f"c{n}") for n in range(6)]
    ws = workspace(tmp_path, remote)
    ws.fetch(shas[-1], depth=3, name="head")
    assert git(ws.tree, "rev-list", "--count", "refs/newsoc/head") == "3"


def test_the_merge_base_can_be_fetched_separately_for_a_secret_range(
    tmp_path: Path, remote: Remote
) -> None:
    base = remote.commit({"f.txt": "0"})
    head = remote.commit({"f.txt": "1"}, "one")
    head = remote.commit({"f.txt": "2"}, "two")
    ws = workspace(tmp_path, remote)
    ws.fetch(head, depth=10, name="head")
    ws.fetch(base, depth=1, name="base")
    rng = ws.merge_base_log_range(base, head)
    assert git(ws.tree, "rev-list", "--count", rng) == "2"


def test_symlinks_are_checked_out_as_plain_files(tmp_path: Path, remote: Remote) -> None:
    (remote.work / "link").symlink_to("/etc/passwd")
    sha = remote.commit({"real.txt": "x"})
    ws = workspace(tmp_path, remote)
    ws.fetch(sha, depth=1, name="head")
    root = ws.checkout(sha)
    assert not (root / "link").is_symlink()
    assert (root / "link").read_text() == "/etc/passwd"  # the target name, not its contents


def test_submodules_are_not_fetched(tmp_path: Path, remote: Remote) -> None:
    (remote.work / ".gitmodules").write_text(
        '[submodule "evil"]\n\tpath = evil\n\turl = https://attacker.invalid/x.git\n'
    )
    (remote.work / "ok.txt").write_text("1")
    git(remote.work, "add", ".gitmodules", "ok.txt")
    # `git add -A` would drop a gitlink with no directory, so stage it by hand.
    git(remote.work, "update-index", "--add", "--cacheinfo", "160000," + "a" * 40 + ",evil")
    git(remote.work, "commit", "--quiet", "-m", "with a submodule")
    git(remote.work, "push", "--quiet", "origin", "main")
    sha = git(remote.work, "rev-parse", "HEAD")
    assert "evil" in git(remote.work, "ls-tree", "HEAD")  # the gitlink really is in the commit
    ws = workspace(tmp_path, remote)
    ws.fetch(sha, depth=1, name="head")
    root = ws.checkout(sha)
    assert (root / "evil").is_dir() and not any((root / "evil").iterdir())


def test_a_second_commit_can_be_checked_out_in_a_separate_worktree(
    tmp_path: Path, remote: Remote
) -> None:
    base = remote.commit({"a.txt": "base"})
    head = remote.commit({"a.txt": "head", "new.txt": "n"})
    ws = workspace(tmp_path, remote)
    ws.fetch(head, depth=5, name="head")
    ws.fetch(base, depth=1, name="base")
    main = ws.checkout(head)
    other = ws.checkout(base, tmp_path / "job" / "base")
    assert (other / "a.txt").read_text() == "base" and not (other / "new.txt").exists()
    assert (main / "a.txt").read_text() == "head"


def test_the_file_protocol_is_refused_unless_enabled(tmp_path: Path, remote: Remote) -> None:
    sha = remote.commit({"a.txt": "1"})
    ws = workspace(tmp_path, remote, allow_file_protocol=False)
    with pytest.raises(GitError):
        ws.fetch(sha, depth=1, name="head")


def test_oversized_checkouts_are_refused(tmp_path: Path, remote: Remote) -> None:
    sha = remote.commit({"big.bin": "x" * 5000})
    ws = workspace(tmp_path, remote, max_bytes=1000)
    ws.fetch(sha, depth=1, name="head")
    with pytest.raises(CheckoutTooLarge):
        ws.checkout(sha)


def test_too_many_files_are_refused(tmp_path: Path, remote: Remote) -> None:
    sha = remote.commit({f"f{n}.txt": "x" for n in range(20)})
    ws = workspace(tmp_path, remote, max_files=10)
    ws.fetch(sha, depth=1, name="head")
    with pytest.raises(CheckoutTooLarge):
        ws.checkout(sha)


def test_cleanup_removes_everything(tmp_path: Path, remote: Remote) -> None:
    sha = remote.commit({"a.txt": "1"})
    ws = workspace(tmp_path, remote)
    ws.fetch(sha, depth=1, name="head")
    ws.checkout(sha)
    ws.cleanup()
    assert not (tmp_path / "job").exists()


# ---- argument validation -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        "--upload-pack=touch /tmp/pwned",
        "-x",
        "main",
        "refs/heads/main",
        "refs/pull/7/merge",
        "refs/pull/7/head; rm -rf /",
        "refs/pull/../../etc/head",
        "A" * 40,
        "a" * 39,
        "a" * 41,
        "",
    ],
)
def test_only_commit_ids_and_pull_heads_may_be_fetched(bad: str) -> None:
    with pytest.raises(GitError):
        valid_fetch_target(bad)


@pytest.mark.parametrize(
    "bad", ["--output=x", "../etc", "a/b/c", "a", "/a", ".hidden/x", "a/..", ""]
)
def test_repository_names_are_validated(bad: str) -> None:
    with pytest.raises(GitError):
        valid_repo(bad)


def test_valid_inputs_pass() -> None:
    assert valid_repo("acme/app-1.x_y") == "acme/app-1.x_y"
    assert valid_sha("0123456789abcdef" * 2 + "01234567") == "0123456789abcdef" * 2 + "01234567"
    assert valid_fetch_target("refs/pull/123/head") == "refs/pull/123/head"


# ---- what git is actually run with --------------------------------------------------------------


@pytest.fixture
def recording_git(tmp_path: Path) -> tuple[Path, Path]:
    """A ``git`` wrapper that logs its arguments and environment, then runs the real git."""
    log = tmp_path / "git-calls.log"
    script = tmp_path / "recording-git"
    script.write_text(
        "#!/bin/bash\n"
        f'echo "ARGV: $*" >> {log}\n'
        f'env | grep -E "^(GIT_|HOME=)" | sed "s/^/ENV: /" >> {log}\n'
        'exec /usr/bin/env git "$@"\n'
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script, log


def test_the_token_is_in_the_environment_and_never_in_argv_or_config(
    tmp_path: Path, remote: Remote, recording_git: tuple[Path, Path]
) -> None:
    script, log = recording_git
    sha = remote.commit({"a.txt": "1"})
    ws = workspace(tmp_path, remote, token=TOKEN, git=str(script))
    ws.fetch(sha, depth=1, name="head")
    ws.checkout(sha)

    text = log.read_text()
    argv_lines = [line for line in text.splitlines() if line.startswith("ARGV:")]
    basic = base64.b64encode(f"x-access-token:{TOKEN}".encode()).decode()
    assert argv_lines and not any(TOKEN in line or basic in line for line in argv_lines)
    assert f"GIT_CONFIG_VALUE_0=Authorization: basic {basic}" in text  # delivered by env
    assert "GIT_CONFIG_KEY_0=http.extraHeader" in text
    config = (ws.tree / ".git" / "config").read_text()
    assert TOKEN not in config and basic not in config and "extraheader" not in config.lower()


def test_git_runs_with_a_minimal_environment_and_safe_options(
    tmp_path: Path,
    remote: Remote,
    recording_git: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "do-not-leak")
    monkeypatch.setenv("GITHUB_TOKEN", "do-not-leak")
    script, log = recording_git
    sha = remote.commit({"a.txt": "1"})
    ws = workspace(tmp_path, remote, git=str(script))
    ws.fetch(sha, depth=1, name="head")
    text = log.read_text()
    assert "do-not-leak" not in text
    for expected in (
        "core.hooksPath=/dev/null",
        "core.symlinks=false",
        "http.followRedirects=false",
        "fetch.fsckObjects=true",
        "GIT_TERMINAL_PROMPT=0",
        "GIT_CONFIG_NOSYSTEM=1",
        "GIT_CONFIG_GLOBAL=/dev/null",
    ):
        assert expected in text, expected
    assert f"HOME={tmp_path / 'job' / 'home'}" in text  # not the user's home


def test_errors_never_contain_the_token(tmp_path: Path, remote: Remote) -> None:
    fake = tmp_path / "failing-git"
    basic = base64.b64encode(f"x-access-token:{TOKEN}".encode()).decode()
    fake.write_text(
        "#!/bin/bash\n"
        + SUBCOMMAND
        + f'[ "$sub" = fetch ] && {{ echo "fatal: auth failed {TOKEN} {basic}" >&2; exit 128; }}\n'
        + 'exec /usr/bin/env git "$@"\n'
    )
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    sha = remote.commit({"a.txt": "1"})
    ws = workspace(tmp_path, remote, token=TOKEN, git=str(fake))
    with pytest.raises(GitError) as err:
        ws.fetch(sha, depth=1, name="head")
    assert "auth failed" in str(err.value)
    assert TOKEN not in str(err.value) and basic not in str(err.value)


def test_a_hung_fetch_is_killed_with_its_children(tmp_path: Path, remote: Remote) -> None:
    pidfile = tmp_path / "child.pid"
    fake = tmp_path / "hanging-git"
    fake.write_text(
        "#!/bin/bash\n"
        + SUBCOMMAND
        + f'if [ "$sub" = fetch ]; then sleep 60 & echo $! > {pidfile}; wait; fi\n'
        + 'exec /usr/bin/env git "$@"\n'
    )
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    sha = remote.commit({"a.txt": "1"})
    ws = workspace(tmp_path, remote, git=str(fake), timeout_s=1)
    with pytest.raises(GitError, match="timed out"):
        ws.fetch(sha, depth=1, name="head")
    child = int(pidfile.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(child, 0)  # the sleep started by the wrapper died with the process group
