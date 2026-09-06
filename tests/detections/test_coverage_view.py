"""Tests for coverage projection and SQL view over reconstruction and promotion events."""

import pytest
from core.detections.coverage import CoverageService


def test_coverage_projection_and_frontier():
    """Verify coverage projection folds reconstruction and promotion events and computes frontier."""
    service = CoverageService()

    events = [
        # Cycle 1: 3 techniques attacked; 2 detected, 1 missed
        {
            "kind": "reconstruction",
            "payload": {
                "environment_id": "staging-range",
                "technique_id": "T1059",
                "cycle_number": 1,
                "verdict": "rule",
                "matching_rules": ["RULE-PS"],
            },
        },
        {
            "kind": "reconstruction",
            "payload": {
                "environment_id": "staging-range",
                "technique_id": "T1021",
                "cycle_number": 1,
                "verdict": "loglm",
                "matching_rules": [],
            },
        },
        {
            "kind": "reconstruction",
            "payload": {
                "environment_id": "staging-range",
                "technique_id": "T1048",
                "cycle_number": 1,
                "verdict": "missed",
                "matching_rules": [],
            },
        },
        # Cycle 2: T1048 promoted; T1003 attacked and missed
        {
            "kind": "promotion",
            "payload": {
                "environment_id": "staging-range",
                "technique_id": "T1048",
                "cycle_number": 2,
                "candidate_id": "cand-exfil-rule",
                "rule_name": "Overlay Exfil Rule",
            },
        },
        {
            "kind": "reconstruction",
            "payload": {
                "environment_id": "staging-range",
                "technique_id": "T1003",
                "cycle_number": 2,
                "verdict": "missed",
                "matching_rules": [],
            },
        },
    ]

    posture = service.project_from_events(events, environment_id="staging-range")

    assert posture.environment_id == "staging-range"
    assert posture.total_techniques_attacked == 4
    # T1059 (rule), T1021 (loglm), T1048 (promoted) are covered = 3
    assert posture.techniques_covered == 3
    # T1003 is missed = 1
    assert posture.techniques_missed == 1

    # Frontier calculation: cycle 1 had 1 missed; cycle 2 had 1 missed
    assert posture.frontier == {1: 1, 2: 1}

    # Frontier direct getter
    frontier = service.get_frontier("staging-range", events=events)
    assert frontier == {1: 1, 2: 1}


def test_replay_from_ledger_reproduces_view_deterministically():
    """Verify replaying the same ledger events twice produces identical coverage posture."""
    service = CoverageService()
    events = [
        {
            "kind": "reconstruction",
            "payload": {
                "environment_id": "prod-twin",
                "technique_id": "T1078",
                "cycle_number": 1,
                "verdict": "both",
                "matching_rules": ["RULE-WHOAMI"],
            },
        },
        {
            "kind": "reconstruction",
            "payload": {
                "environment_id": "prod-twin",
                "technique_id": "T1047",
                "cycle_number": 1,
                "verdict": "missed",
                "matching_rules": [],
            },
        },
    ]

    run1 = service.project_from_events(events, environment_id="prod-twin")
    run2 = service.project_from_events(events, environment_id="prod-twin")

    assert run1.frontier == run2.frontier
    assert run1.coverage_by_layer == run2.coverage_by_layer
    assert run1.total_techniques_attacked == run2.total_techniques_attacked
