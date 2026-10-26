"""Make sure the scanner image exists on the Docker host, building it if it does not.

A deployed worker is itself a container; it cannot rely on someone having built
``newsoc/scanners`` on the host. The image is tagged with a hash of its Dockerfile, so editing
the Dockerfile (for example, bumping a scanner version) builds a new image the next time a
worker starts, and an unchanged Dockerfile is never rebuilt.
"""

from __future__ import annotations

import hashlib
import logging
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path

log = logging.getLogger("newsoc.image")

REPOSITORY = "newsoc/scanners"
BUILD_TIMEOUT_S = 30 * 60

Run = Callable[..., subprocess.CompletedProcess[str]]


class ImageBuildError(RuntimeError):
    pass


def tag_for(dockerfile: Path, repository: str = REPOSITORY) -> str:
    return f"{repository}:{hashlib.sha256(dockerfile.read_bytes()).hexdigest()[:12]}"


def ensure_image(
    dockerfile: Path,
    docker_cmd: Sequence[str] = ("docker",),
    run: Run = subprocess.run,
    timeout_s: int = BUILD_TIMEOUT_S,
) -> str:
    """Return the image tag for ``dockerfile``, building it first if the host lacks it."""
    tag = tag_for(dockerfile)
    probe = run(
        [*docker_cmd, "image", "inspect", tag],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    if probe.returncode == 0:
        return tag

    log.info("building scanner image %s (this takes a few minutes the first time)", tag)
    with tempfile.TemporaryDirectory(prefix="newsoc-build-") as empty_context:
        # The Dockerfile downloads everything it needs, so the build context is empty.
        done = run(
            [*docker_cmd, "build", "--tag", tag, "--file", str(dockerfile), empty_context],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_s,
        )
    if done.returncode != 0:
        raise ImageBuildError(f"building {tag} failed:\n{(done.stdout + done.stderr)[-1500:]}")
    log.info("scanner image %s is ready", tag)
    return tag
