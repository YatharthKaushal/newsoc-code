from __future__ import annotations

import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from newsoc_code import osvdb
from newsoc_code.scan import install_rules, rules_version


def make_rules(root: Path, body: str = "rules: []") -> Path:
    (root / "js").mkdir(parents=True)
    (root / "js" / "a.yaml").write_text(body)
    (root / "js" / "a.js").write_text("// test")
    return root


def test_rules_are_copied_and_stay_identical(tmp_path: Path) -> None:
    src = make_rules(tmp_path / "src")
    dest = install_rules(src, tmp_path / "shared" / "rules")
    assert (dest / "js" / "a.yaml").read_text() == "rules: []"
    assert rules_version(dest) == rules_version(src)  # same pack, same version hash


def test_a_stale_install_is_replaced_not_merged(tmp_path: Path) -> None:
    dest = tmp_path / "rules"
    make_rules(dest, "old")
    (dest / "removed-rule.yaml").write_text("gone")
    src = make_rules(tmp_path / "src", "new")

    install_rules(src, dest)

    assert (dest / "js" / "a.yaml").read_text() == "new"
    assert not (dest / "removed-rule.yaml").exists()


def test_installed_rules_are_readable_by_the_unprivileged_scanners(tmp_path: Path) -> None:
    src = make_rules(tmp_path / "src")
    (src / "js" / "a.yaml").chmod(0o600)
    dest = install_rules(src, tmp_path / "rules")
    assert stat.S_IMODE((dest / "js" / "a.yaml").stat().st_mode) == 0o644
    assert stat.S_IMODE((dest / "js").stat().st_mode) == 0o755


def test_installing_onto_itself_changes_nothing(tmp_path: Path) -> None:
    src = make_rules(tmp_path / "src")
    assert install_rules(src, src) == src
    assert (src / "js" / "a.yaml").exists()


# ---- keeping the vulnerability database fresh ------------------------------------------------


class Clock:
    def __init__(self) -> None:
        # Snapshot age comes from real file times, so the fake clock starts at the real time.
        self.now = datetime.now(UTC)

    def __call__(self) -> datetime:
        return self.now


def fake_downloader(calls: list[Path], fail: bool = False):
    def download(snapshot: Path) -> None:
        calls.append(snapshot)
        if fail:
            raise RuntimeError("no network")
        for eco in osvdb.ECOSYSTEMS:
            target = snapshot / "osv-scalibr" / eco / "all.zip"
            target.parent.mkdir(parents=True)
            import zipfile

            with zipfile.ZipFile(target, "w") as z:
                z.writestr("a.json", "x" * osvdb.MIN_ZIP_BYTES)

    return download


def test_refresh_happens_when_there_is_no_snapshot(tmp_path: Path) -> None:
    calls: list[Path] = []
    refresher = osvdb.Refresher(tmp_path, fake_downloader(calls), timedelta(hours=6), Clock())
    assert refresher.due() and refresher.run_if_due()
    assert len(calls) == 1 and osvdb.current(tmp_path) is not None


def test_a_fresh_snapshot_is_left_alone(tmp_path: Path) -> None:
    calls: list[Path] = []
    # A snapshot's age is read from its files' modification times, so this one uses the real clock.
    refresher = osvdb.Refresher(tmp_path, fake_downloader(calls), timedelta(hours=6))
    assert refresher.run_if_due()
    assert not refresher.due() and not refresher.run_if_due()
    assert len(calls) == 1


def test_an_old_snapshot_is_refreshed(tmp_path: Path) -> None:
    calls: list[Path] = []
    clock = Clock()
    refresher = osvdb.Refresher(tmp_path, fake_downloader(calls), timedelta(hours=6), clock)
    refresher.run_if_due()
    clock.now += timedelta(hours=7)
    assert refresher.due() and refresher.run_if_due()
    assert len(calls) == 2


def test_a_failed_refresh_is_not_retried_immediately(tmp_path: Path) -> None:
    calls: list[Path] = []
    clock = Clock()
    refresher = osvdb.Refresher(
        tmp_path, fake_downloader(calls, fail=True), timedelta(hours=6), clock
    )

    with pytest.raises(RuntimeError):
        refresher.run_if_due()
    assert not refresher.due()  # backing off
    clock.now += osvdb.REFRESH_RETRY + timedelta(seconds=1)
    assert refresher.due()
    with pytest.raises(RuntimeError):
        refresher.run_if_due()
    assert len(calls) == 2
