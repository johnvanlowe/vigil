"""Tests for verdict export and anonymity filtering."""

import json
import os
import tempfile
import jsonschema
import pytest

from core.findings.export import anonymize_verdict_row, redact_text, export_verdicts


def test_redact_text_strips_sensitive_entities():
    """Verify IP, host, and user redaction."""
    text_sample = "Connection from 192.168.1.100 to server-01.corp.local by DOMAIN\\admin_john on 10.0.0.0/24"
    redacted = redact_text(text_sample)

    assert "192.168.1.100" not in redacted
    assert "server-01.corp.local" not in redacted
    assert "DOMAIN\\admin_john" not in redacted
    assert "10.0.0.0/24" not in redacted
    assert "[REDACTED_IP]" in redacted
    assert "[REDACTED_HOST]" in redacted
    assert "[REDACTED_USER]" in redacted
    assert "[REDACTED_SUBNET]" in redacted


def test_anonymized_row_validates_against_json_schema():
    """Verify that anonymize_verdict_row outputs data conforming to data/schemas/verdict_export_v1.json."""
    raw_event = {
        "run_id": "verdict-101",
        "payload": {
            "action": "dismiss",
            "source": "ui",
            "reason": "Scanner False Positive from 10.1.2.3",
            "new_severity": "low",
            "attack_mapping": [
                {"tactic": "Discovery", "technique_id": "T1046"}
            ],
            "loglm_provenance": {
                "score": 0.92,
                "target": "db.corp.local",
                "raw_log": "SELECT * FROM users",
            },
        },
    }

    row, shape = anonymize_verdict_row(raw_event)
    assert row["schema_version"] == 1
    assert "10.1.2.3" not in row["reason_category"]
    assert row["anonymized_features"]["raw_log"] == "[WITHHELD_SENSITIVE_TEXT]"

    schema_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../../data/schemas/verdict_export_v1.json")
    )
    with open(schema_path) as f:
        schema = json.load(f)

    jsonschema.validate(instance=row, schema=schema)
