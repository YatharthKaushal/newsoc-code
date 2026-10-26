"""The contracts/ schemas stay in step with the Python models and the policy loader."""

from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft7Validator, Draft202012Validator

from newsoc_code.policy.loader import load_policy

ROOT = Path(__file__).parents[2]
CONTRACTS = ROOT / "contracts"
sys.path.insert(0, str(ROOT / "scripts"))
import export_contracts  # noqa: E402  (a script, not a package)

TODAY = date(2026, 10, 26)


class _YamlWithoutDates(yaml.SafeLoader):
    """Reads ``2026-12-31`` as the string the schema expects, not as a date object.

    This is the rule for any implementation: convert YAML timestamps to strings before
    validating a policy file against contracts/policy.schema.json.
    """


_YamlWithoutDates.yaml_implicit_resolvers = {
    key: [(tag, rx) for tag, rx in resolvers if tag != "tag:yaml.org,2002:timestamp"]
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def parse_yaml(text: str):
    return yaml.load(text, Loader=_YamlWithoutDates)


POLICY_SCHEMA = json.loads((CONTRACTS / "policy.schema.json").read_text())


@pytest.mark.parametrize("name", sorted(export_contracts.generated()))
def test_committed_schema_matches_the_python_model(name):
    committed = json.loads((CONTRACTS / name).read_text())
    assert committed == export_contracts.generated()[name], (
        f"{name} is stale: run `uv run python scripts/export_contracts.py`"
    )


def test_generated_schemas_are_valid_json_schema():
    for schema in export_contracts.generated().values():
        Draft202012Validator.check_schema(schema)


def test_finding_schema_accepts_a_real_finding_and_rejects_a_bad_one():
    from tests.factories import finding

    schema = export_contracts.generated()["finding.schema.json"]
    good = json.loads(finding().model_dump_json())
    Draft202012Validator(schema).validate(good)
    bad = {**good, "severity": "catastrophic"}
    assert list(Draft202012Validator(schema).iter_errors(bad))


def test_policy_schema_is_valid_draft7():
    Draft7Validator.check_schema(POLICY_SCHEMA)


VECTOR_POLICIES = [
    json.loads(p.read_text())["policy_yaml"]
    for p in sorted((CONTRACTS / "vectors" / "policy").glob("*.json"))
]


@pytest.mark.parametrize("text", VECTOR_POLICIES)
def test_schema_and_loader_agree_on_every_vector_policy(text):
    document = parse_yaml(text)
    schema_valid = not list(Draft7Validator(POLICY_SCHEMA).iter_errors(document))
    loader_valid = not load_policy(text, TODAY).invalid
    assert schema_valid == loader_valid, text


@pytest.mark.parametrize(
    "text",
    [
        "version: 2\n",
        "mode: yolo\n",
        "waivers:\n  - rule: CWE-79\n    approved_by: me\n",
        "gates:\n  merge:\n    block_on: [catastrophic]\n",
    ],
)
def test_schema_rejects_what_the_loader_rejects(text):
    assert list(Draft7Validator(POLICY_SCHEMA).iter_errors(parse_yaml(text)))
    assert load_policy(text, TODAY).invalid
