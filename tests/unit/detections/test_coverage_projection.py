"""Unit tests for the coverage projection fold over the append-only Ledger."""

import pytest

from core.detections.coverage_projection import fold_coverage_projection


@pytest.mark.unit
def test_coverage_projection_pure_fold():
    """Verify pure fold over agent_events computes accurate coverage, gaps, and layer breakdown."""
    events = [
        # Cycle 1: Red Plan targeting T1059.001 and T1003
        {
            "seq": 1,
            "ts": "2026-09-04T10:00:00Z",
            "kind": "red_plan",
            "payload": {
                "plan_id": "plan-c1",
                "environment_id": "env-range",
                "steps": [
                    {"step_id": "s1", "technique_id": "T1059.001"},
                    {"step_id": "s2", "technique_id": "T1003"},
                ],
                "metadata": {"cycle_number": 1},
            },
        },
        # Cycle 1: Reconstruction - s1 detected by rule, s2 missed
        {
            "seq": 2,
            "ts": "2026-09-04T10:05:00Z",
            "kind": "reconstruction_verdict",
            "payload": {
                "environment_id": "env-range",
                "verdict": {
                    "step_id": "s1",
                    "technique_id": "T1059.001",
                    "verdict": "detected_by_rule",
                },
            },
        },
        {
            "seq": 3,
            "ts": "2026-09-04T10:06:00Z",
            "kind": "reconstruction_verdict",
            "payload": {
                "environment_id": "env-range",
                "verdict": {
                    "step_id": "s2",
                    "technique_id": "T1003",
                    "verdict": "missed",
                },
            },
        },
        # Cycle 1: Promotion of new detection for T1003 closing the gap!
        {
            "seq": 4,
            "ts": "2026-09-04T10:15:00Z",
            "kind": "detection_promotion",
            "payload": {
                "environment_id": "env-range",
                "technique_id": "T1003",
                "name": "Sigma Mimikatz LSASS Dump",
            },
        },
        # Cycle 2: Red Plan forced onto T1021.001 (RDP)
        {
            "seq": 5,
            "ts": "2026-09-04T11:00:00Z",
            "kind": "red_plan",
            "payload": {
                "plan_id": "plan-c2",
                "environment_id": "env-range",
                "steps": [
                    {"step_id": "s3", "technique_id": "T1021.001"},
                ],
                "metadata": {"cycle_number": 2},
            },
        },
        # Cycle 2: Reconstruction - s3 detected by LogLM only
        {
            "seq": 6,
            "ts": "2026-09-04T11:05:00Z",
            "kind": "reconstruction_verdict",
            "payload": {
                "environment_id": "env-range",
                "verdict": {
                    "step_id": "s3",
                    "technique_id": "T1021.001",
                    "verdict": "detected_by_loglm",
                },
            },
        },
    ]

    proj = fold_coverage_projection(events, "env-range")

    assert proj.environment_id == "env-range"
    assert proj.total_cycles == 2
    assert set(proj.attacked_techniques) == {"T1059.001", "T1003", "T1021.001"}

    # Coverage by layer
    assert proj.technique_coverage["T1059.001"] == "rule"
    assert proj.technique_coverage["T1003"] == "rule"  # closed by promotion
    assert proj.technique_coverage["T1021.001"] == "loglm"

    # Promoted detections
    assert len(proj.promoted_detections) == 1
    assert proj.promoted_detections[0]["technique_id"] == "T1003"

    # Cycle history
    assert len(proj.cycle_history) == 2
    assert proj.cycle_history[0].cycle_number == 1
    assert proj.cycle_history[1].cycle_number == 2

    # LogLM frontier summary
    assert "residual_novelty" in proj.loglm_frontier_summary
    assert proj.loglm_frontier_summary["posture_trajectory"] == "tightening"


@pytest.mark.unit
def test_coverage_projection_byte_for_byte_reproducibility():
    """Verify that folding over identical Ledger events produces identical projection."""
    events = [
        {
            "seq": 1,
            "ts": "2026-09-04T10:00:00Z",
            "kind": "red_plan",
            "payload": {
                "plan_id": "plan-det",
                "environment_id": "env-prod-test",
                "steps": [{"step_id": "s1", "technique_id": "T1059.001"}],
                "metadata": {"cycle_number": 1},
            },
        },
        {
            "seq": 2,
            "ts": "2026-09-04T10:05:00Z",
            "kind": "reconstruction_verdict",
            "payload": {
                "environment_id": "env-prod-test",
                "verdict": {"step_id": "s1", "technique_id": "T1059.001", "verdict": "both"},
            },
        },
    ]

    p1 = fold_coverage_projection(events, "env-prod-test")
    p2 = fold_coverage_projection(events, "env-prod-test")

    # Byte-for-byte equivalence (excluding timestamp)
    d1 = p1.model_dump(exclude={"folded_at"})
    d2 = p2.model_dump(exclude={"folded_at"})
    assert d1 == d2
