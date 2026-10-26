"""A real bare git repository that behaves like GitHub for the fetches newsoc performs."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

ENV = {
    "PATH": os.environ["PATH"],
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.com",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.com",
}


def git(cwd: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", *args], cwd=cwd, env=ENV, capture_output=True, text=True, check=True
    )
    return done.stdout.strip()


class Remote:
    """A bare repository plus a working clone to author commits in."""

    def __init__(self, base: Path) -> None:
        self.bare = base / "remote.git"
        self.work = base / "work"
        self.work.mkdir(parents=True)
        git(base, "init", "--bare", "--quiet", str(self.bare))
        git(self.bare, "config", "uploadpack.allowAnySHA1InWant", "true")
        git(self.work, "init", "--quiet", "-b", "main")
        git(self.work, "remote", "add", "origin", str(self.bare))

    @property
    def url(self) -> str:
        return f"file://{self.bare}"

    def commit(self, files: dict[str, str | None], message: str = "c", branch: str = "main") -> str:
        """Commit on ``branch`` (created from the current HEAD if new) and push it.

        A value of None deletes the file.
        """
        current = git(self.work, "symbolic-ref", "--short", "HEAD")
        if current != branch:
            if git(self.work, "branch", "--list", branch):
                git(self.work, "checkout", "--quiet", branch)
            else:
                git(self.work, "checkout", "--quiet", "-b", branch)
        for name, content in files.items():
            path = self.work / name
            if content is None:
                path.unlink()
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        git(self.work, "add", "-A")
        git(self.work, "commit", "--quiet", "--allow-empty", "-m", message)
        sha = git(self.work, "rev-parse", "HEAD")
        git(self.work, "push", "--quiet", "--force", "origin", branch)
        return sha

    def checkout(self, branch: str) -> None:
        git(self.work, "checkout", "--quiet", branch)

    def pull_ref(self, number: int, sha: str) -> None:
        git(self.bare, "update-ref", f"refs/pull/{number}/head", sha)

    def merge_base(self, a: str, b: str) -> str:
        return git(self.work, "merge-base", a, b)

    def ahead_by(self, base: str, head: str) -> int:
        return int(git(self.work, "rev-list", "--count", f"{base}..{head}"))

    def changed(self, base: str, head: str) -> list[tuple[str, str, str | None]]:
        """(status, path, previous path) for ``base...head``, as GitHub's compare reports it."""
        out = git(self.work, "diff", "--name-status", "-M", f"{base}...{head}")
        changes: list[tuple[str, str, str | None]] = []
        for line in out.splitlines():
            parts = line.split("\t")
            if parts[0].startswith("R"):
                changes.append(("renamed", parts[2], parts[1]))
            else:
                status = {"A": "added", "D": "removed", "M": "modified"}[parts[0][0]]
                changes.append((status, parts[1], None))
        return changes
