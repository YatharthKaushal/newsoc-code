"""The offline OSV vulnerability database used by the SCA scanner.

Scanners run with no network, so the database is downloaded by a separate job (this module)
that DOES have network access, into a new snapshot directory. Once verified, a ``current``
symlink is swapped to it atomically, so a scan never sees a half-written database. Scans mount
the snapshot read-only.

Staleness: over 48 hours old is a warning; over 7 days the SCA category is "Not assessed",
because a silently outdated database would report vulnerable dependencies as clean.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import zipfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

ECOSYSTEMS = ("npm", "PyPI")
SNAPSHOT_PREFIX = "snapshot-"
CURRENT = "current"
WARN_AFTER = timedelta(hours=48)
FAIL_AFTER = timedelta(days=7)
MIN_ZIP_BYTES = 100_000  # a real ecosystem database is megabytes; this catches empty downloads
KEEP_SNAPSHOTS = 2

Downloader = Callable[[Path], None]


class StaleDatabaseError(ValueError):
    """Raised when the database is too old to trust."""


@dataclass(frozen=True)
class DbStatus:
    path: Path
    age: timedelta
    warning: str | None = None


def _zip_path(snapshot: Path, ecosystem: str) -> Path:
    return snapshot / "osv-scalibr" / ecosystem / "all.zip"


def verify(snapshot: Path) -> list[str]:
    """Problems with a snapshot; an empty list means it is usable."""
    problems = []
    for eco in ECOSYSTEMS:
        zp = _zip_path(snapshot, eco)
        if not zp.is_file():
            problems.append(f"{eco}: database file is missing")
        elif zp.stat().st_size < MIN_ZIP_BYTES:
            problems.append(
                f"{eco}: database file is suspiciously small ({zp.stat().st_size} bytes)"
            )
        elif not zipfile.is_zipfile(zp):
            problems.append(f"{eco}: database file is not a valid zip")
    return problems


def age_of(snapshot: Path, now: datetime | None = None) -> timedelta:
    """Age of the oldest ecosystem file in a snapshot."""
    now = now or datetime.now(UTC)
    mtimes = [
        _zip_path(snapshot, e).stat().st_mtime
        for e in ECOSYSTEMS
        if _zip_path(snapshot, e).is_file()
    ]
    if not mtimes:
        raise StaleDatabaseError(f"{snapshot} contains no OSV database files")
    return now - datetime.fromtimestamp(min(mtimes), UTC)


def check(snapshot: Path | None, now: datetime | None = None) -> DbStatus:
    """Decide whether a snapshot may be used. Raises StaleDatabaseError if it must not be."""
    if snapshot is None or not snapshot.exists():
        raise StaleDatabaseError("no OSV database is available; run `newsoc refresh-osv`")
    age = age_of(snapshot, now)
    days = age.total_seconds() / 86400
    if age > FAIL_AFTER:
        raise StaleDatabaseError(f"OSV database is {days:.0f} days old (limit 7): refresh required")
    warning = f"OSV database is {days:.1f} days old (refresh is due)" if age > WARN_AFTER else None
    return DbStatus(snapshot, age, warning)


def current(db_root: Path) -> Path | None:
    link = db_root / CURRENT
    return link.resolve() if link.exists() else None


def refresh(db_root: Path, downloader: Downloader, now: datetime | None = None) -> Path:
    """Download into a new snapshot, verify it, then swap ``current`` atomically."""
    db_root.mkdir(parents=True, exist_ok=True)
    stamp = (now or datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")
    snapshot = db_root / f"{SNAPSHOT_PREFIX}{stamp}"
    snapshot.mkdir()
    try:
        downloader(snapshot)
        if problems := verify(snapshot):
            raise RuntimeError(
                "downloaded OSV database failed verification: " + "; ".join(problems)
            )
        _seal(snapshot)
    except BaseException:
        shutil.rmtree(snapshot, ignore_errors=True)  # never leave a partial snapshot behind
        raise

    staging = db_root / f"{CURRENT}.new"
    staging.unlink(missing_ok=True)
    staging.symlink_to(snapshot.name)  # relative link inside db_root
    os.replace(staging, db_root / CURRENT)  # atomic on POSIX
    _prune(db_root, keep=KEEP_SNAPSHOTS)
    return snapshot


def _seal(snapshot: Path) -> None:
    """The downloader opens the directory for the container user; close it again once verified."""
    for path in [snapshot, *snapshot.rglob("*")]:
        path.chmod(0o755 if path.is_dir() else 0o644)


def _prune(db_root: Path, keep: int) -> None:
    snapshots = sorted(
        p for p in db_root.iterdir() if p.name.startswith(SNAPSHOT_PREFIX) and p.is_dir()
    )
    live = (db_root / CURRENT).resolve()
    for old in snapshots[:-keep] if keep else snapshots:
        if old.resolve() != live:
            shutil.rmtree(old, ignore_errors=True)


def docker_downloader(
    image: str, docker_cmd: Sequence[str] = ("docker",), user: str | None = None
) -> Downloader:
    """Download with OSV-Scanner itself, in a container that is allowed network access.

    This is the ONE place a newsoc container has a network, and it only ever runs this fixed
    command on a seed project of our own, never on customer code. A tiny project with an npm
    lockfile and a PyPI requirements file makes OSV-Scanner fetch exactly those two databases.
    """
    uid = user or f"{os.getuid()}:{os.getgid()}"

    def download(snapshot: Path) -> None:
        with tempfile.TemporaryDirectory(prefix="newsoc-osv-seed-") as seed_dir:
            seed = Path(seed_dir)
            (seed / "package-lock.json").write_text(
                '{"name":"seed","lockfileVersion":3,"requires":true,"packages":{"":{"name":"seed"},'
                '"node_modules/lodash":{"version":"4.17.15",'
                '"resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz"}}}'
            )
            (seed / "requirements.txt").write_text("requests==2.19.0\n")
            seed.chmod(0o755)
            snapshot.chmod(0o777)
            cmd = [
                *docker_cmd,
                "run",
                "--rm",
                "--user",
                uid,
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,size=256m,mode=1777",  # noqa: S108
                "-v",
                f"{snapshot.resolve()}:/osvdb:rw",
                "-v",
                f"{seed}:/src:ro",
                "-e",
                "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/osvdb",
                image,
                "osv-scanner",
                "scan",
                "source",
                "-r",
                "/src",
                "--offline-vulnerabilities",
                "--download-offline-databases",
                "--format",
                "json",
                "--output-file",
                "/tmp/seed.json",  # noqa: S108 (tmpfs inside the container)
            ]
            done = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=900)  # noqa: S603
            if done.returncode not in (0, 1):  # 1 just means the seed has known vulnerabilities
                raise RuntimeError(f"osv-scanner database download failed: {done.stderr[-500:]}")

    return download
