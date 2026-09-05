"""Unit tests for the live-fire evaluation gate (reseeded retest and quiet-on-benign)."""

import pytest

from core.detections.candidate import DetectionCandidate
from core.detections.live_fire import LiveFireService


@pytest.mark.unit
def test_live_fire_passes_when_generalizing_and_quiet():
    """Verify live-fire gate passes when rule fires on reseeded attack and is quiet on benign traffic."""
    service = LiveFireService()

    behavioral_sigma = """
title: Behavioral PowerShell Obfuscation Detection
detection:
  selection:
    Image|endswith:
      - '\\powershell.exe'
      - '\\pwsh.exe'
    CommandLine|contains:
      - '-encodedcommand'
      - '-enc'
"""
    candidate = DetectionCandidate(
        gap_technique_id="T1059.001",
        name="Behavioral PowerShell",
        rule_content=behavioral_sigma,
        format="sigma",
    )

    benign_baseline = [
        {
            "event_id": "benign-1",
            "source": "sysmon",
            "details": {"process_name": "explorer.exe", "command_line": "explorer.exe /idlist,:0"},
        },
        {
            "event_id": "benign-2",
            "source": "sysmon",
            "details": {"process_name": "chrome.exe", "command_line": "chrome.exe --type=renderer"},
        },
    ]

    result = service.evaluate_live_fire(
        candidate=candidate,
        benign_baseline_telemetry=benign_baseline,
        reseed=99,
    )

    assert result.passed is True
    assert result.retest_fired is True
    assert result.quiet_on_benign is True
    assert result.benign_false_positives_count == 0


@pytest.mark.unit
def test_live_fire_rejects_when_failing_retest_generalization():
    """Regression test: candidate that passed backtest but fails reseeded retest is rejected."""
    service = LiveFireService()

    # Rule that overfitted / failed on variant
    candidate = DetectionCandidate(
        gap_technique_id="T1059.001",
        name="Overfitted Rule",
        rule_content="detection: { selection: { CommandLine: 'exact_first_run_command_only' } }",
        format="sigma",
    )

    result = service.evaluate_live_fire(
        candidate=candidate,
        benign_baseline_telemetry=[],
        reseed=42,
        force_retest_miss=True,
    )

    assert result.passed is False
    assert result.retest_fired is False
    assert "failed to fire on independently seeded attack variant" in (result.rejection_reason or "")


@pytest.mark.unit
def test_live_fire_rejects_when_noisy_on_benign_baseline():
    """Verify live-fire gate rejects candidate that fires on benign traffic (false-positive prevention)."""
    service = LiveFireService()

    # Overly broad rule that matches 'whoami'
    broad_rule = """
title: Overly Broad Discovery
detection:
  selection:
    CommandLine|contains: 'whoami'
"""
    candidate = DetectionCandidate(
        gap_technique_id="T1033",
        name="Overly Broad Whoami",
        rule_content=broad_rule,
        format="sigma",
    )

    # Benign estate traffic where automated logon scripts run 'whoami'
    benign_baseline = [
        {
            "event_id": "benign-script-1",
            "source": "sysmon",
            "details": {"process_name": "whoami.exe", "command_line": "whoami"},
        }
    ]

    result = service.evaluate_live_fire(
        candidate=candidate,
        benign_baseline_telemetry=benign_baseline,
        reseed=55,
    )

    assert result.passed is False
    assert result.quiet_on_benign is False
    assert result.benign_false_positives_count > 0
    assert "false positive alerts on benign baseline estate traffic" in (result.rejection_reason or "")
