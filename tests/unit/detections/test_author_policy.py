"""Unit tests for the author-or-defer choice, checkpoints, and promotion policy."""

import pytest

from core.detections.author_policy import (
    AuthoringPolicy,
    GapDecision,
    GapTriageService,
)
from core.detections.candidate import (
    CandidateStatus,
    DetectionCandidate,
    ValidationRecord,
)


@pytest.mark.unit
def test_up_front_policy_auto_authoring():
    """Verify up-front policy auto-authors when confidence and priority satisfy thresholds."""
    policy = AuthoringPolicy(
        default_action="auto_author",
        min_confidence=0.90,
        auto_author_min_severity="high",
    )
    triage = GapTriageService(run_id="run-triage-1", policy=policy)

    gap = {
        "step_id": "step-gap-1",
        "technique_id": "T1486",
        "priority": "high",
    }

    decision = triage.triage_gap(gap, confidence=0.95)

    assert decision["decision"] == GapDecision.AUTHOR_NOW.value
    assert "policy_auto" in decision["decided_by"]
    assert "step-gap-1" in triage.decisions


@pytest.mark.unit
def test_operator_resolution_recording():
    """Verify operator resolution to gap triage is recorded with reason."""
    triage = GapTriageService(run_id="run-triage-2")

    record = triage.record_operator_resolution(
        step_id="step-scan-1",
        decision=GapDecision.ACCEPT_GAP,
        reason="Sanctioned vulnerability scanning activity by security operations",
        resolved_by="lead_analyst",
    )

    assert record["decision"] == GapDecision.ACCEPT_GAP.value
    assert record["decided_by"] == "lead_analyst"
    assert "Sanctioned vulnerability scanning" in record["reason"]


@pytest.mark.unit
def test_demote_yourself_only_promotion_enforcement():
    """Verify promotion requires valid validation record and authorized human approval."""
    triage = GapTriageService(run_id="run-promote-1")

    unvalidated_candidate = DetectionCandidate(
        gap_technique_id="T1059.001",
        name="Unvalidated Rule",
        rule_content="detection: ...",
    )

    # 1. Unvalidated candidate cannot be promoted
    promoted = triage.promote_candidate(unvalidated_candidate, authorized_by="sec_admin")
    assert promoted is False
    assert unvalidated_candidate.status == CandidateStatus.DRAFT

    # 2. Validated candidate requires human approval (agent cannot promote itself)
    validated_candidate = DetectionCandidate(
        gap_technique_id="T1059.001",
        name="Validated Rule",
        rule_content="detection: ...",
        validation=ValidationRecord(is_valid=True),
        status=CandidateStatus.VALIDATED,
    )

    # Rejected when agent attempts promotion
    promoted = triage.promote_candidate(validated_candidate, authorized_by="agent")
    assert promoted is False

    # Accepted when authorized human promotes
    promoted = triage.promote_candidate(validated_candidate, authorized_by="alice@corp.com")
    assert promoted is True
    assert validated_candidate.status == CandidateStatus.PROMOTED
    assert validated_candidate.promoted_at is not None
