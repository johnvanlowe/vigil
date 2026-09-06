"""Tests for author-or-defer checkpoints, autonomy policy gating, and promotion."""

import pytest
from core.agents.loop_checkpoints import (
    GapAction,
    GapCheckpoint,
    LoopCheckpointManager,
)
from core.detections.candidates import CandidateStatus, DetectionCandidate
from core.policies.schema import Policy, PolicyKind


def test_upfront_autonomy_policy_auto_authors_above_threshold():
    """Verify up-front Policy(kind=autonomy) auto-authors when confidence exceeds threshold."""
    mgr = LoopCheckpointManager()
    policy = Policy(
        id="pol-autonomy-01",
        kind=PolicyKind.AUTONOMY,
        scope="loop_authoring",
        params={"auto_author_threshold": 0.75},
        promoted_by="secops-lead",
    )

    gap = {
        "step_id": "step-wmi",
        "technique_id": "T1047",
        "action_name": "WMI lateral",
        "environment_id": "staging-range",
    }

    # High confidence -> auto-author permitted without raising checkpoint
    auto_authored, checkpoint = mgr.evaluate_gap_autonomy(
        gap, autonomy_policy=policy, confidence=0.85
    )
    assert auto_authored is True
    assert checkpoint is None


def test_gap_below_threshold_raises_checkpoint_requiring_resolution():
    """Verify gap below threshold raises checkpoint requiring resolution with reason."""
    mgr = LoopCheckpointManager()
    policy = Policy(
        id="pol-autonomy-02",
        kind=PolicyKind.AUTONOMY,
        scope="loop_authoring",
        params={"auto_author_threshold": 0.90},
        promoted_by="secops-lead",
    )

    gap = {
        "step_id": "step-stealth-exfil",
        "technique_id": "T1048",
        "action_name": "Alternative protocol exfil",
        "environment_id": "staging-range",
    }

    # Low confidence -> raises checkpoint
    auto_authored, checkpoint = mgr.evaluate_gap_autonomy(
        gap, autonomy_policy=policy, confidence=0.70
    )
    assert auto_authored is False
    assert isinstance(checkpoint, GapCheckpoint)
    assert checkpoint.technique_id == "T1048"

    # Resolving without reason fails
    with pytest.raises(ValueError, match="reason is required"):
        mgr.resolve_checkpoint(checkpoint.checkpoint_id, GapAction.DEFER, reason="")

    # Resolve with accept_gap
    resolution = mgr.resolve_checkpoint(
        checkpoint_id=checkpoint.checkpoint_id,
        action=GapAction.ACCEPT_GAP,
        reason="Legacy protocol allowed per architecture exception 2026-04",
        actor="john.analyst",
    )
    assert resolution.action == GapAction.ACCEPT_GAP
    assert resolution.actor == "john.analyst"
    assert checkpoint.status == "resolved"


def test_promotion_requires_human_or_pre_authorized_policy():
    """Verify candidate promotion requires human actor or pre-authorized policy."""
    mgr = LoopCheckpointManager()
    candidate = DetectionCandidate(
        candidate_id="cand-promo-01",
        environment_id="staging-range",
        technique_id="T1047",
        rule_name="WMI Process Creation Rule",
        rule_content="title: Test Rule",
        rationale="Validated rule",
    )

    # Agent/system promotion without pre-authorization is blocked
    with pytest.raises(PermissionError, match="Promotion to live overlay requires an authorized human"):
        mgr.promote_candidate(candidate, actor="agent")

    # Human promotion succeeds
    promoted = mgr.promote_candidate(candidate, actor="john.senior_analyst")
    assert promoted is True
    assert candidate.status == CandidateStatus.PROMOTED

    # Pre-authorized policy promotion succeeds even with system actor
    pre_auth_policy = Policy(
        id="pol-autonomy-preauth",
        kind=PolicyKind.AUTONOMY,
        scope="loop_promotion",
        params={"pre_authorized_promotion": True},
        promoted_by="ciso",
    )
    cand2 = DetectionCandidate(
        candidate_id="cand-promo-02",
        environment_id="staging-range",
        technique_id="T1021",
        rule_name="SMB Admin Rule",
        rule_content="title: Test Rule 2",
        rationale="Pre-authorized",
    )
    promoted2 = mgr.promote_candidate(cand2, actor="system", autonomy_policy=pre_auth_policy)
    assert promoted2 is True
    assert cand2.status == CandidateStatus.PROMOTED
