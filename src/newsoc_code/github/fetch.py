"""Fetch a repository's code for scanning, safely.

The code is hostile until proven otherwise, and the installation token is valuable. So:

* The token travels in the environment of the git process (``GIT_CONFIG_*`` injects an
  ``http.extraHeader``), never in argv (visible to other users in ``ps``), the remote URL, or
  ``.git/config``. It never enters a scanner container: this runs in the worker, outside Docker.
* git runs with a minimal environment, no global or system config, no hooks, no credential
  prompts, no redirects (so the header cannot follow a redirect to another host), no LFS
  smudge, no submodules, and only the https protocol.
* ``core.symlinks=false`` writes symlinks as small text files, so nothing scanning the tree can
  be steered outside it. ``fetch.fsckObjects`` rejects malformed or malicious git objects.
* Every value passed to git as an argument is validated first.
* A timeout kills git's whole process group, and the size of the checkout is capped.

Fetches are shallow: the head commit with a bounded history for the secrets scan, and the
merge base on its own.
"""

from __future__ import annotations

import base64
import os
import re
import shutil
import signal
import subprocess
from pathlib import Path

DEFAULT_TIMEOUT_S = 300
MAX_CHECKOUT_BYTES = 1024 * 1024 * 1024
MAX_CHECKOUT_FILES = 200_000
MAX_HISTORY_DEPTH = 500

_SHA = re.compile(r"^[0-9a-f]{40}$")
_REPO = re.compile(r"^[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}$")
_PULL_REF = re.compile(r"^refs/pull/[0-9]{1,9}/head$")
_NAME = re.compile(r"^[a-z][a-z0-9-]{0,30}$")

# Options git runs with on every command. None of these are secret.
_SAFE_CONFIG = (
    "core.hooksPath=/dev/null",
    "core.symlinks=false",
    "core.fsmonitor=false",
    "core.autocrlf=false",
    "core.sparseCheckout=false",
    "gc.auto=0",
    "advice.detachedHead=false",
    "protocol.version=2",
    "http.followRedirects=false",
    "fetch.fsckObjects=true",
    "transfer.fsckObjects=true",
    "submodule.recurse=false",
    "fetch.recurseSubmodules=false",
)


class GitError(Exception):
    """A git operation failed. The message has had credentials removed."""


class StaleHead(GitError):
    """The ref no longer points at the commit we were asked to scan (the author pushed again)."""


class CheckoutTooLarge(GitError):
    """The checkout exceeds the size or file-count limit."""


def valid_sha(value: str) -> str:
    if not _SHA.match(value):
        raise GitError(f"not a commit id: {value[:20]!r}")
    return value


def valid_repo(full_name: str) -> str:
    if not _REPO.match(full_name) or full_name.startswith(".") or ".." in full_name:
        raise GitError(f"not a repository name: {full_name[:50]!r}")
    return full_name


def valid_fetch_target(target: str) -> str:
    """A commit id, or a pull request head ref."""
    if _SHA.match(target) or _PULL_REF.match(target):
        return target
    raise GitError(f"refusing to fetch {target[:50]!r}")


class Workspace:
    """One repository checkout in a private directory, removed with ``cleanup()``."""

    def __init__(
        self,
        root: Path,
        remote_url: str,
        token: str | None = None,
        *,
        timeout_s: int = DEFAULT_TIMEOUT_S,
        git: str = "git",
        allow_file_protocol: bool = False,
        max_bytes: int = MAX_CHECKOUT_BYTES,
        max_files: int = MAX_CHECKOUT_FILES,
    ) -> None:
        self.root = root
        self.tree = root / "repo"
        self._home = root / "home"
        self._remote_url = remote_url
        self._token = token
        self._timeout_s = timeout_s
        self._git = git
        self._allow_file = allow_file_protocol  # tests clone from local directories
        self._max_bytes = max_bytes
        self._max_files = max_files

    # ---- plumbing --------------------------------------------------------------------------

    def _env(self) -> dict[str, str]:
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(self._home),
            "LANG": "C.UTF-8",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_LFS_SKIP_SMUDGE": "1",
            "GIT_PROTOCOL_FROM_USER": "0",
            "GIT_ALLOW_PROTOCOL": "https:file" if self._allow_file else "https",
        }
        if self._token:
            basic = base64.b64encode(f"x-access-token:{self._token}".encode()).decode()
            env["GIT_CONFIG_COUNT"] = "1"
            env["GIT_CONFIG_KEY_0"] = "http.extraHeader"
            env["GIT_CONFIG_VALUE_0"] = f"Authorization: basic {basic}"
        return env

    def _scrub(self, text: str) -> str:
        if self._token:
            basic = base64.b64encode(f"x-access-token:{self._token}".encode()).decode()
            text = text.replace(self._token, "***").replace(basic, "***")
        return text

    def _run(self, *args: str, cwd: Path | None = None, timeout_s: int | None = None) -> str:
        cmd = [self._git]
        for option in _SAFE_CONFIG:
            cmd += ["-c", option]
        cmd += list(args)
        proc = subprocess.Popen(  # noqa: S603
            cmd,
            cwd=cwd or self.tree,
            env=self._env(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            start_new_session=True,  # so a timeout can kill git and its helpers together
        )
        try:
            out, err = proc.communicate(timeout=timeout_s or self._timeout_s)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate()
            raise GitError(
                f"git {args[0]} timed out after {timeout_s or self._timeout_s}s"
            ) from None
        if proc.returncode != 0:
            raise GitError(f"git {args[0]} failed: {self._scrub(err.strip())[-400:]}")
        return out

    # ---- operations ------------------------------------------------------------------------

    def init(self) -> None:
        self._home.mkdir(parents=True, exist_ok=True)
        self.tree.mkdir(parents=True, exist_ok=True)
        self._run("init", "--quiet", cwd=self.tree)
        self._run("remote", "add", "origin", self._remote_url)

    def fetch(self, target: str, *, depth: int, name: str, expect_sha: str | None = None) -> str:
        """Fetch a commit (by id) or pull request head, keep it as ``refs/newsoc/<name>``, and
        return its commit id. ``expect_sha`` makes a moved pull request raise ``StaleHead``."""
        valid_fetch_target(target)
        if not _NAME.match(name):
            raise GitError(f"bad ref name {name!r}")
        depth = max(1, min(depth, MAX_HISTORY_DEPTH))
        self._run("fetch", "--quiet", "--no-tags", "--depth", str(depth), "origin", target)
        sha = valid_sha(self._run("rev-parse", "--verify", "FETCH_HEAD^{commit}").strip())
        if expect_sha is not None and sha != expect_sha:
            raise StaleHead(f"{target} is now {sha[:10]}, expected {expect_sha[:10]}")
        self._run("update-ref", f"refs/newsoc/{name}", sha)
        return sha

    def checkout(self, sha: str, dest: Path | None = None) -> Path:
        """Check ``sha`` out into the main tree, or into a separate directory (a worktree)."""
        valid_sha(sha)
        if dest is None:
            self._run("checkout", "--quiet", "--detach", "--force", sha)
            path = self.tree
        else:
            self._run("worktree", "add", "--quiet", "--detach", "--force", str(dest), sha)
            path = dest
        self._check_size(path)
        return path

    def merge_base_log_range(self, merge_base: str, head: str) -> str:
        return f"{valid_sha(merge_base)}..{valid_sha(head)}"

    def _check_size(self, path: Path) -> None:
        total = files = 0
        for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
            if ".git" in dirnames:
                dirnames.remove(".git")
            for filename in filenames:
                files += 1
                try:
                    total += (Path(dirpath) / filename).lstat().st_size
                except OSError:
                    continue
                if total > self._max_bytes or files > self._max_files:
                    raise CheckoutTooLarge(
                        f"repository exceeds the limit ({self._max_files} files, "
                        f"{self._max_bytes // (1024 * 1024)} MiB)"
                    )

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)
