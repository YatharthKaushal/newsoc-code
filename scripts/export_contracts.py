#!/usr/bin/env python3
"""Regenerate the JSON Schemas in contracts/ from the Python models.

    uv run python scripts/export_contracts.py

The schema for the policy YAML (contracts/policy.schema.json) is written by hand because the
YAML shape differs from the internal model; tests keep it consistent with the loader.
"""

from __future__ import annotations

import json
from pathlib import Path

from newsoc_code.findings.schema import Finding, ScanResult

CONTRACTS = Path(__file__).resolve().parents[1] / "contracts"


def generated() -> dict[str, dict]:
    return {
        "finding.schema.json": Finding.model_json_schema(),
        "scan-result.schema.json": ScanResult.model_json_schema(),
    }


def main() -> None:
    for name, schema in generated().items():
        (CONTRACTS / name).write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n")
        print("wrote", CONTRACTS / name)


if __name__ == "__main__":
    main()
