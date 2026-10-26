from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from newsoc_code.runner.docker import DockerRunner, RootUserRefused, resolve_user
from newsoc_code.runner.image import ImageBuildError, ensure_image, tag_for


class FakeDocker:
    """Records docker invocations; ``have_image`` says whether ``image inspect`` succeeds."""

    def __init__(self, have_image: bool = False, build_ok: bool = True) -> None:
        self.have_image, self.build_ok = have_image, build_ok
        self.calls: list[list[str]] = []

    def __call__(self, cmd: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
        self.calls.append(cmd)
        if "inspect" in cmd:
            return subprocess.CompletedProcess(cmd, 0 if self.have_image else 1, "", "")
        return subprocess.CompletedProcess(
            cmd, 0 if self.build_ok else 1, "step 1/9", "" if self.build_ok else "pip: no network"
        )


@pytest.fixture
def dockerfile(tmp_path: Path) -> Path:
    path = tmp_path / "scanners.Dockerfile"
    path.write_text("FROM scratch\n")
    return path


# ---- never run scanners as root ----------------------------------------------------------------


@pytest.mark.parametrize("user", ["0:0", "0", "root", "root:root", "0:1000"])
def test_root_is_refused(user: str) -> None:
    with pytest.raises(RootUserRefused):
        resolve_user(user)
    with pytest.raises(RootUserRefused):
        DockerRunner(user=user)


def test_a_worker_running_as_root_must_name_an_unprivileged_scanner_user(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("os.getuid", lambda: 0)
    with pytest.raises(RootUserRefused):
        DockerRunner()
    assert DockerRunner(user="1000:1000").user == "1000:1000"


def test_the_default_user_is_the_current_unprivileged_user(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("os.getuid", lambda: 1000)
    monkeypatch.setattr("os.getgid", lambda: 1001)
    assert resolve_user(None) == "1000:1001"


def test_the_refusal_also_protects_the_database_download(monkeypatch: pytest.MonkeyPatch) -> None:
    from newsoc_code import osvdb

    monkeypatch.setattr("os.getuid", lambda: 0)
    with pytest.raises(RootUserRefused):
        osvdb.docker_downloader("img")


# ---- the scanner image --------------------------------------------------------------------------


def test_the_tag_follows_the_dockerfile_content(tmp_path: Path, dockerfile: Path) -> None:
    first = tag_for(dockerfile)
    assert first.startswith("newsoc/scanners:") and len(first.split(":")[1]) == 12
    assert tag_for(dockerfile) == first
    dockerfile.write_text("FROM scratch\nRUN true\n")
    assert tag_for(dockerfile) != first


def test_an_existing_image_is_not_rebuilt(dockerfile: Path) -> None:
    fake = FakeDocker(have_image=True)
    assert ensure_image(dockerfile, run=fake) == tag_for(dockerfile)
    assert len(fake.calls) == 1 and "build" not in fake.calls[0]


def test_a_missing_image_is_built_from_an_empty_context(dockerfile: Path) -> None:
    fake = FakeDocker(have_image=False)
    tag = ensure_image(dockerfile, run=fake)
    build = fake.calls[-1]
    assert build[:2] == ["docker", "build"] and tag in build and str(dockerfile) in build
    context = Path(build[-1])
    assert context != dockerfile.parent  # the repository is not sent to the daemon
    assert not context.exists()  # the temporary empty context is cleaned up


def test_a_failed_build_reports_the_tail_of_the_output(dockerfile: Path) -> None:
    with pytest.raises(ImageBuildError, match="no network"):
        ensure_image(dockerfile, run=FakeDocker(build_ok=False))
