"""Baselines: which findings already exist on the base branch.

A baseline is just the set of fingerprints from a scan of the merge-base. Fingerprints exclude
line numbers, so moving code around does not turn old findings into "new" ones.
"""

from __future__ import annotations

import json
from pathlib import Path

from newsoc_code.findings.schema import ScanResult, ScanStatus


def from_results(results: list[ScanResult]) -> frozenset[str]:
    return frozenset(f.fingerprint for r in results for f in r.findings)


def assessed(results: list[ScanResult]) -> bool:
    """True only if every applicable scanner produced a trustworthy result.

    A baseline built from a partly failed scan would make missing findings look "new", or worse,
    make real findings look old. Callers must treat an unassessed baseline as unavailable.
    """
    return all(r.status in (ScanStatus.OK, ScanStatus.NOT_APPLICABLE) for r in results)


def save(path: Path, fingerprints: frozenset[str]) -> None:
    path.write_text(json.dumps(sorted(fingerprints)), encoding="utf-8")


def load(path: Path) -> frozenset[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list) or not all(isinstance(x, str) for x in data):
        raise ValueError(f"{path} is not a JSON list of fingerprints")
    return frozenset(data)
