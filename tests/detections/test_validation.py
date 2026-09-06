"""Tests for validation harness: lint, replay, repair budget, and audit records."""

from pathlib import Path
import pytest

from core.detections.candidates import CandidateStatus, DetectionCandidate, ValidationRecord
from core.detections.validation import (
    lint_candidate,
    replay_candidate,
    skill_validate_detection,
)
from core.integrations.offensive.stub import StubOffensiveEngine


def test_validation_skill_manifest_and_function():
    """Verify SKILL.md exists with schema_version: 1 and skill_validate_detection is callable."""
    skill_path = Path(__file__).resolve().parents[2] / "skills" / "validate_detection" / "SKILL.md"
    assert skill_path.exists()
    content = skill_path.read_text(encoding="utf-8")
    assert "schema_version: 1" in content
    assert callable(skill_validate_detection)


def test_candidate_keyed_to_literal_host_rejected_with_guidance():
    """Regression test: candidate keyed to a literal host is rejected with rewrite guidance."""
    brittle_rule = """
title: Brittle Host Detection
logsource:
  category: process_creation
detection:
  selection:
    ComputerName: srv-dc-01.range.corp
    CommandLine|contains: whoami
  condition: selection
"""
    candidate = DetectionCandidate(
        candidate_id="cand-brittle-01",
        environment_id="staging-range",
        technique_id="T1033",
        rule_name="Brittle Host Rule",
        rule_content=brittle_rule,
        rationale="Detects whoami on srv-dc-01",
    )

    lint_res = lint_candidate(candidate)
    assert lint_res.passed is False
    assert lint_res.anti_brittleness_passed is False
    assert any("Host: srv-dc-01.range.corp" in lit for lit in lint_res.detected_literals)
    assert lint_res.rewrite_guidance is not None
    assert "Rewrite guidance" in lint_res.rewrite_guidance

    # Validation harness gate verification
    record = skill_validate_detection(candidate, captured_telemetry=[])
    assert record.is_valid is False
    assert record.passed_lint is False
    assert candidate.status == CandidateStatus.REJECTED


def test_candidate_matching_no_activity_rejected():
    """Regression test: candidate matching no captured telemetry activity is rejected."""
    rule = """
title: Unmatched Rule
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith: nonexistent_malware.exe
  condition: selection
"""
    candidate = DetectionCandidate(
        candidate_id="cand-unmatched-01",
        environment_id="staging-range",
        technique_id="T1059",
        rule_name="Unmatched Rule",
        rule_content=rule,
        rationale="Testing replay non-match",
    )

    stub = StubOffensiveEngine()
    telemetry = stub.load_fixture_telemetry()

    record = skill_validate_detection(candidate, captured_telemetry=telemetry)
    assert record.is_valid is False
    assert record.passed_lint is True
    assert record.passed_replay is False
    assert record.replay_matches_count == 0
    assert "matched 0 events" in record.error


def test_valid_candidate_clears_gates_and_writes_ledger_record():
    """Verify valid behavioral candidate matching telemetry passes all gates and records ValidationRecord."""
    valid_rule = """
title: Behavioral WMI Detection
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - wmic
      - process call create
  condition: selection
"""
    candidate = DetectionCandidate(
        candidate_id="cand-valid-01",
        environment_id="staging-range",
        technique_id="T1047",
        rule_name="Behavioral WMI Detection",
        rule_content=valid_rule,
        rationale="Behavioral detection for WMI lateral process creation",
    )

    stub = StubOffensiveEngine()
    telemetry = stub.load_fixture_telemetry()

    record = skill_validate_detection(
        candidate=candidate,
        captured_telemetry=telemetry,
        repair_attempts=1,
        judge_verdict=True,
    )

    assert isinstance(record, ValidationRecord)
    assert record.is_valid is True
    assert record.passed_lint is True
    assert record.passed_replay is True
    assert record.passed_judge is True
    assert record.replay_matches_count >= 1
    assert candidate.status == CandidateStatus.VALIDATED
