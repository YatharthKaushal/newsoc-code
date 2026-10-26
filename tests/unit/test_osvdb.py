"""Snapshot refresh, atomic swap, rollback and the staleness rules."""

from __future__ import annotations

import os
import time
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import builders as fx
import pytest

from newsoc_code import osvdb
from newsoc_code.findings.schema import ScanStatus
from newsoc_code.scan import run_adapter
from newsoc_code.scanners.osv import OsvAdapter
from tests.conftest import run_output


class NeverRun:
    """A runner that fails the test if a scan is attempted."""

    def run(self, spec):
        raise AssertionError("the scanner must not run")


def write_db(snapshot: Path, *, age: timedelta = timedelta(0), size: int = 300_000) -> Path:
    """A snapshot with a believable (incompressible-ish, large enough) zip per ecosystem."""
    for eco in osvdb.ECOSYSTEMS:
        zp = snapshot / "osv-scalibr" / eco / "all.zip"
        zp.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(zp, "w", zipfile.ZIP_STORED) as z:
            z.writestr("GHSA-test.json", os.urandom(size))
        stamp = time.time() - age.total_seconds()
        os.utime(zp, (stamp, stamp))
    return snapshot


def fake_downloader(**kw):
    return lambda snapshot: write_db(snapshot, **kw)


def test_refresh_creates_a_verified_snapshot_and_points_current_at_it(tmp_path):
    snap = osvdb.refresh(tmp_path, fake_downloader())
    assert snap.parent == tmp_path and snap.name.startswith("snapshot-")
    assert osvdb.current(tmp_path) == snap.resolve()
    assert osvdb.verify(snap) == []
    assert not (tmp_path / "current.new").exists()  # the staging link is gone after the swap


def test_second_refresh_swaps_current_and_prunes_old_snapshots(tmp_path):
    first = osvdb.refresh(tmp_path, fake_downloader(), now=datetime(2026, 10, 1, tzinfo=UTC))
    second = osvdb.refresh(tmp_path, fake_downloader(), now=datetime(2026, 10, 2, tzinfo=UTC))
    third = osvdb.refresh(tmp_path, fake_downloader(), now=datetime(2026, 10, 3, tzinfo=UTC))

    assert osvdb.current(tmp_path) == third.resolve()
    assert not first.exists()  # only the newest two are kept
    assert second.exists() and third.exists()


@pytest.mark.parametrize(
    ("downloader", "expect"),
    [
        (fake_downloader(size=100), "suspiciously small"),
        (lambda s: None, "missing"),
    ],
    ids=["tiny-download", "nothing-downloaded"],
)
def test_a_bad_download_is_discarded_and_current_is_untouched(tmp_path, downloader, expect):
    good = osvdb.refresh(tmp_path, fake_downloader(), now=datetime(2026, 10, 1, tzinfo=UTC))

    with pytest.raises(RuntimeError, match=expect):
        osvdb.refresh(tmp_path, downloader, now=datetime(2026, 10, 2, tzinfo=UTC))

    assert osvdb.current(tmp_path) == good.resolve()
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith("snapshot-")] == [good.name]


def test_a_downloader_that_crashes_leaves_no_partial_snapshot(tmp_path):
    def boom(snapshot: Path) -> None:
        (snapshot / "partial").write_text("x")
        raise OSError("network went away")

    with pytest.raises(OSError, match="network went away"):
        osvdb.refresh(tmp_path, boom)
    assert [p for p in tmp_path.iterdir() if p.name != "current"] == []
    assert osvdb.current(tmp_path) is None


def test_a_non_zip_file_fails_verification(tmp_path):
    snap = write_db(tmp_path / "s")
    (snap / "osv-scalibr" / "npm" / "all.zip").write_bytes(b"not a zip" * 50_000)
    assert any("not a valid zip" in p for p in osvdb.verify(snap))


# ---- staleness: 48 h warns, 7 days refuses -----------------------------------------------------


def test_a_fresh_database_is_accepted_without_warning(tmp_path):
    status = osvdb.check(write_db(tmp_path / "s", age=timedelta(hours=3)))
    assert status.warning is None


def test_a_three_day_old_database_warns(tmp_path):
    status = osvdb.check(write_db(tmp_path / "s", age=timedelta(days=3)))
    assert status.warning and "refresh is due" in status.warning


def test_database_older_than_a_week_is_refused(tmp_path):
    with pytest.raises(osvdb.StaleDatabaseError, match="refresh required"):
        osvdb.check(write_db(tmp_path / "s", age=timedelta(days=8)))


def test_the_age_is_the_oldest_ecosystem_file(tmp_path):
    snap = write_db(tmp_path / "s", age=timedelta(hours=1))
    old = time.time() - timedelta(days=9).total_seconds()
    os.utime(snap / "osv-scalibr" / "PyPI" / "all.zip", (old, old))
    with pytest.raises(osvdb.StaleDatabaseError):
        osvdb.check(snap)


def test_missing_database_is_an_error_with_a_next_step(tmp_path):
    with pytest.raises(osvdb.StaleDatabaseError, match="newsoc refresh-osv"):
        osvdb.check(None)
    with pytest.raises(osvdb.StaleDatabaseError):
        osvdb.check(tmp_path / "does-not-exist")


# ---- the scanner must never report "clean" on an outdated database ---------------------------


def test_osv_adapter_fails_instead_of_scanning_with_a_stale_database(tmp_path, make_ctx):
    src = tmp_path / "src"
    fx.make_js_app(src)
    ctx = make_ctx(src, osv_db_dir=write_db(tmp_path / "db", age=timedelta(days=9)))

    result = run_adapter(OsvAdapter(), ctx, NeverRun())

    assert result.status is ScanStatus.FAILED
    assert "refresh required" in (result.reason or "")
    assert result.assessment().value == "Not assessed"


def test_osv_adapter_fails_when_no_database_is_configured(tmp_path, make_ctx):
    src = tmp_path / "src"
    fx.make_js_app(src)
    result = run_adapter(OsvAdapter(), make_ctx(src, osv_db_dir=None), NeverRun())
    assert result.status is ScanStatus.FAILED and "newsoc refresh-osv" in (result.reason or "")


def test_osv_adapter_adds_a_warning_note_for_a_ageing_database(tmp_path, make_ctx, place_report):
    src = tmp_path / "src"
    fx.make_js_app(src)
    fx.make_py_app(src)
    ctx = make_ctx(src, osv_db_dir=write_db(tmp_path / "db", age=timedelta(days=3)))
    place_report(ctx, "osv/npm-and-pypi.json", "osv.json")

    result = OsvAdapter().parse(ctx, run_output(1))

    assert result.status is ScanStatus.OK
    assert any("refresh is due" in n for n in result.notes)
    assert result.db_snapshot == "db"


def test_a_verified_snapshot_is_not_world_writable(tmp_path):
    snap = osvdb.refresh(tmp_path, fake_downloader(), now=datetime(2026, 10, 1, tzinfo=UTC))
    assert snap.stat().st_mode & 0o777 == 0o755
    assert (snap / "osv-scalibr" / "npm" / "all.zip").stat().st_mode & 0o777 == 0o644
