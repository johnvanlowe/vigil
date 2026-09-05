"""Unit tests for the deterministic validation harness (lint, replay, independent review)."""

import pytest

from core.detections.candidate import (
    CandidateStatus,
    DetectionCandidate,
)
from core.detections.validation_harness import ValidationHarness


@pytest.mark.unit
def test_lint_rejects_brittle_environment_literals():
    """Verify Gate 1 hard rule: candidate tied to literal IP, host, or user is rejected."""
    harness = ValidationHarness()

    # Rule keyed to specific IP and hostname (brittle!)
    brittle_yaml = """
title: Suspicious PowerShell from Specific Host
id: test-brittle-1
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ComputerName: 'workstation-42.corp.local'
    DestinationIp: '192.168.1.105'
    CommandLine|contains: 'powershell.exe'
  condition: selection
level: high
"""
    candidate = DetectionCandidate(
        gap_technique_id="T1059.001",
        name="Brittle Rule",
        rule_content=brittle_yaml,
        format="sigma",
    )

    result = harness.lint_candidate(candidate)

    assert result.passed is False
    assert result.anti_brittleness_passed is False
    assert len(result.detected_literals) > 0
    assert any("192.168.1.105" in lit for lit in result.detected_literals)
    assert any("workstation-42" in lit for lit in result.detected_literals)
    assert "Rewrite around behavioral signals" in (result.rewrite_guidance or "")


@pytest.mark.unit
def test_lint_accepts_clean_behavioral_rule():
    """Verify Gate 1 accepts clean behavioral detections free of environmental literals."""
    harness = ValidationHarness()

    behavioral_yaml = """
title: Suspicious Encoded PowerShell Invocation
id: test-clean-1
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith:
      - '\\powershell.exe'
      - '\\pwsh.exe'
    CommandLine|contains:
      - '-enc'
      - '-w hidden'
  condition: selection
level: high
"""
    candidate = DetectionCandidate(
        gap_technique_id="T1059.001",
        name="Clean Behavioral Rule",
        rule_content=behavioral_yaml,
        format="sigma",
    )

    result = harness.lint_candidate(candidate)

    assert result.passed is True
    assert result.syntax_valid is True
    assert result.anti_brittleness_passed is True
    assert result.detected_literals == []


@pytest.mark.unit
def test_replay_backtest_matching():
    """Verify Gate 2 passes on matching activity and rejects candidate that matches nothing."""
    harness = ValidationHarness()

    rule_yaml = """
title: Suspicious Encoded PowerShell
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: '-enc'
"""
    candidate = DetectionCandidate(
        gap_technique_id="T1059.001",
        name="PowerShell Rule",
        rule_content=rule_yaml,
        format="sigma",
    )

    # Telemetry that matches
    matching_telemetry = [
        {
            "event_id": "ev-match-1",
            "technique_id": "T1059.001",
            "action": "powershell.exe -enc aW52b2tl...",
            "details": {"process_name": "powershell.exe", "command_line": "-enc aW52b2tl"},
        }
    ]

    res_pass = harness.replay_candidate(candidate, matching_telemetry)
    assert res_pass.passed is True
    assert res_pass.matched_events_count == 1
    assert "ev-match-1" in res_pass.matched_event_ids

    # Telemetry for a completely different technique with no matching keywords
    unrelated_telemetry = [
        {
            "event_id": "ev-unrelated-2",
            "technique_id": "T1078",
            "action": "login",
            "details": {"login_type": "interactive"},
        }
    ]

    res_fail = harness.replay_candidate(candidate, unrelated_telemetry)
    assert res_fail.passed is False
    assert res_fail.matched_events_count == 0
    assert "matches 0 events" in (res_fail.reason or "")


@pytest.mark.unit
def test_full_validation_gauntlet():
    """Verify complete validation run updates candidate status and records verdicts."""
    harness = ValidationHarness()

    valid_yaml = """
title: Mimikatz Execution Detection
id: test-mimikatz-1
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - 'sekurlsa'
      - 'minidump'
  condition: selection
level: high
"""
    candidate = DetectionCandidate(
        gap_technique_id="T1003",
        name="Mimikatz Detection",
        rule_content=valid_yaml,
        format="sigma",
    )

    telemetry = [
        {
            "event_id": "ev-mimi-1",
            "technique_id": "T1003",
            "action": "procdump.exe minidump lsass.exe",
            "details": {"command_line": "minidump lsass.exe"},
        }
    ]

    record = harness.validate_candidate(candidate, telemetry)

    assert record.is_valid is True
    assert candidate.status == CandidateStatus.VALIDATED
    assert record.lint_result.passed is True
    assert record.replay_result.passed is True
    assert record.review_result.passed is True
    assert record.review_result.score >= 0.70
