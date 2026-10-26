"""Stable fingerprints for dedupe, baselines and waivers.

Rules that make a fingerprint useful:
* Never include a line number: findings must survive unrelated edits above them.
* Normalise whitespace in matched text so reformatting does not create "new" findings.
* Never include a secret value. Secrets are represented by a keyed hash so the same secret
  can be matched across commits without the value ever being stored.

``SCHEME_VERSION`` must be raised whenever the inputs of any fingerprint change. Cached
baselines are keyed on it (see ``pipeline.scanner_key``), so fingerprints made under another
scheme are never compared with new ones.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from pathlib import PurePosixPath

SCHEME_VERSION = 2  # 2: SCA fingerprints use the project directory instead of the lockfile path

_WS = re.compile(r"\s+")
_PYPI_SEPARATORS = re.compile(r"[-_.]+")
_SEP = "\x1f"


def normalise_text(text: str) -> str:
    return _WS.sub(" ", text).strip()


def _digest(*parts: str) -> str:
    return hashlib.sha256(_SEP.join(parts).encode("utf-8")).hexdigest()


def sast_fingerprint(rule_id: str, path: str, match_text: str, occurrence: int) -> str:
    """``occurrence`` is the index of this match among identical matches of the rule in the file."""
    return _digest("sast", rule_id, path, normalise_text(match_text), str(occurrence))


def _clean_dir(directory: str) -> str:
    cleaned = PurePosixPath(directory.replace("\\", "/")).as_posix()
    return "" if cleaned == "." else cleaned.lstrip("/")


def project_dir(manifest_path: str) -> str:
    """The directory of a lockfile or manifest, relative to the repository root.

    POSIX separators, no leading ``./`` or ``/``, and ``""`` for the repository root.
    """
    return _clean_dir(str(PurePosixPath(manifest_path.replace("\\", "/")).parent))


def normalise_package(ecosystem: str, name: str) -> str:
    """Case-folded package name; PyPI names also fold ``-``, ``_`` and ``.`` (PEP 503)."""
    folded = name.lower()
    return _PYPI_SEPARATORS.sub("-", folded) if ecosystem.lower() == "pypi" else folded


def sca_fingerprint(ecosystem: str, package: str, directory: str, vuln_id: str) -> str:
    """Identity of one vulnerable dependency in one project directory.

    ``directory`` is the folder holding the lockfile(s), not a lockfile path (see
    ``project_dir``). Two lockfiles in one folder (``package-lock.json`` and ``yarn.lock``)
    describe the same dependency tree, so they are one finding, and the fingerprint must
    survive either file being added or removed. Neither the version nor the line is part of it:
    a bump that leaves the advisory unfixed is not a new finding.
    """
    return _digest(
        "sca-project",
        ecosystem.lower(),
        normalise_package(ecosystem, package),
        _clean_dir(directory),
        vuln_id,
    )


def secret_hash(value: str, salt: bytes) -> str:
    """Keyed hash of a secret value. The value itself is discarded by the caller."""
    return hmac.new(salt, value.encode("utf-8"), hashlib.sha256).hexdigest()


def secrets_fingerprint(rule_id: str, hashed_value: str) -> str:
    """The path is deliberately excluded: one secret is one finding with several locations."""
    return _digest("secrets", rule_id, hashed_value)


def iac_fingerprint(check_id: str, path: str, resource: str) -> str:
    return _digest("iac", check_id, path, resource)
