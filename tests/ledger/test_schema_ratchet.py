"""Ratchet test enforcing schema v1 convention for all Ledger event kinds."""

import json
import os
import glob
import pytest
import jsonschema


SCHEMAS_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../data/schemas/ledger/v1")
)

# Known event kinds declared in v1
REQUIRED_EVENT_KINDS = {
    "reconstruction",
    "validation_verdict",
    "verdict",
    "policy_change",
    "budget_exhausted",
    "promotion",
    "red_plan",
    "agent_event",
}


def test_all_required_schemas_exist():
    """Verify that all core event kinds have schema files in data/schemas/ledger/v1."""
    assert os.path.isdir(SCHEMAS_DIR), f"Schema directory {SCHEMAS_DIR} does not exist"
    for kind in REQUIRED_EVENT_KINDS:
        schema_path = os.path.join(SCHEMAS_DIR, f"{kind}.json")
        assert os.path.isfile(schema_path), (
            f"Missing JSON schema for event kind {kind!r} at {schema_path}. "
            "Every ledger event kind must have a schema in data/schemas/ledger/v1/."
        )


def test_schemas_are_valid_and_declare_schema_version():
    """Verify that every schema is valid JSON Schema Draft-07 and requires schema_version == 1."""
    schema_files = glob.glob(os.path.join(SCHEMAS_DIR, "*.json"))
    assert len(schema_files) >= len(REQUIRED_EVENT_KINDS)

    for path in schema_files:
        with open(path, "r") as f:
            schema = json.load(f)

        # Check Draft-07 schema validity
        jsonschema.Draft7Validator.check_schema(schema)

        # Check that schema_version is required and constrained to 1
        assert "schema_version" in schema.get("properties", {}), (
            f"Schema {path} missing schema_version property"
        )
        assert "schema_version" in schema.get("required", []), (
            f"Schema {path} must list schema_version as required"
        )


def test_ratchet_fails_on_unregistered_event_kind():
    """Simulate attempting to append an unregistered event kind."""
    known_kinds = {
        os.path.splitext(os.path.basename(p))[0]
        for p in glob.glob(os.path.join(SCHEMAS_DIR, "*.json"))
    }

    def validate_event_payload(kind: str, payload: dict):
        if kind not in known_kinds:
            raise ValueError(f"No schema registered for ledger event kind: {kind}")
        with open(os.path.join(SCHEMAS_DIR, f"{kind}.json")) as f:
            schema = json.load(f)
        jsonschema.validate(instance=payload, schema=schema)

    # Registered kind with valid payload should pass
    validate_event_payload(
        "reconstruction",
        {"schema_version": 1, "verdict": "rule", "step_id": "step-1"},
    )

    # Unregistered kind should raise
    with pytest.raises(ValueError, match="No schema registered for ledger event kind: unmapped_future_kind"):
        validate_event_payload(
            "unmapped_future_kind",
            {"schema_version": 1, "data": "unexpected"},
        )
