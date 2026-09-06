"""Unit tests for Policy and PolicyChange governance schemas."""

import pytest
from core.policies.schema import (
    Policy,
    PolicyChange,
    PolicyChangeDirection,
    PolicyKind,
)


def test_policy_instantiation_with_all_kinds():
    """Verify that Policy supports autonomy, budget, suppression, offensive, and sla kinds."""
    for kind in PolicyKind:
        policy = Policy(
            kind=kind,
            scope="investigation",
            params={"threshold": 0.9},
            ttl=3600,
            promoted_by="analyst_alice",
        )
        assert policy.kind == kind
        assert policy.id.startswith("pol-")
        assert policy.scope == "investigation"
        assert policy.params["threshold"] == 0.9
        assert policy.ttl == 3600
        assert policy.promoted_by == "analyst_alice"


def test_policy_change_tighten_allowed_for_any_actor():
    """Tightening a policy is always allowed and does not strictly require dwell."""
    change = PolicyChange(
        policy_id="pol-123",
        kind=PolicyKind.AUTONOMY,
        direction=PolicyChangeDirection.TIGHTEN,
        actor="system",
        reason="Automated demotion after repeated false positives",
        new_params={"auto_approve_threshold": 0.95},
    )
    # Should not raise
    change.validate_loosen_ratchet()
    assert change.direction == PolicyChangeDirection.TIGHTEN


def test_policy_change_loosen_requires_human_actor_and_dwell():
    """Loosening a policy requires a non-system human actor and dwell_seconds."""
    # Automated actor attempting to loosen policy
    with pytest.raises(ValueError, match="requires a verified human actor"):
        change = PolicyChange(
            policy_id="pol-123",
            kind=PolicyKind.AUTONOMY,
            direction=PolicyChangeDirection.LOOSEN,
            actor="agent",
            reason="Want wider autonomy",
            dwell_seconds=300,
        )
        change.validate_loosen_ratchet()

    # Missing dwell
    with pytest.raises(ValueError, match="recording a positive dwell_seconds"):
        change = PolicyChange(
            policy_id="pol-123",
            kind=PolicyKind.BUDGET,
            direction=PolicyChangeDirection.LOOSEN,
            actor="ciso_bob",
            reason="Emergency incident response budget expansion",
            dwell_seconds=None,
        )
        change.validate_loosen_ratchet()

    # Human actor with dwell succeeds
    valid_loosen = PolicyChange(
        policy_id="pol-123",
        kind=PolicyKind.BUDGET,
        direction=PolicyChangeDirection.LOOSEN,
        actor="ciso_bob",
        reason="Approved emergency budget expansion",
        dwell_seconds=600,
        new_params={"max_cost_usd": 100.0},
    )
    valid_loosen.validate_loosen_ratchet()
