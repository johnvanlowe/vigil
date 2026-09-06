"""Tests for PolicyService and governance policy persistence."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.policies.models import PolicyModel
from core.policies.schema import Policy, PolicyChangeDirection, PolicyKind
from core.policies.service import PolicyService, DEFAULT_AUTONOMY_THRESHOLDS


@pytest.fixture
def policy_service():
    engine = create_engine("sqlite:///:memory:")
    PolicyModel.__table__.create(engine)
    SessionLocal = sessionmaker(bind=engine)
    return PolicyService(session_factory=SessionLocal)


def test_policy_thresholds_fallback_and_override(policy_service):
    """Verify that get_autonomy_thresholds returns defaults and respects overrides."""
    # Initially defaults
    thresholds = policy_service.get_autonomy_thresholds()
    assert thresholds["auto_approve"] == DEFAULT_AUTONOMY_THRESHOLDS["auto_approve"]
    assert thresholds["manual_review"] == DEFAULT_AUTONOMY_THRESHOLDS["manual_review"]

    # Tighten policy (e.g. higher bar for auto approval)
    policy = Policy(
        kind=PolicyKind.AUTONOMY,
        scope="*",
        params={"auto_approve": 0.95, "manual_review": 0.88},
    )
    policy_service.set_policy(
        policy,
        actor="lead_analyst",
        reason="Tightening auto-approval criteria for sensitive environment",
        direction=PolicyChangeDirection.TIGHTEN,
    )

    updated_thresholds = policy_service.get_autonomy_thresholds()
    assert updated_thresholds["auto_approve"] == 0.95
    assert updated_thresholds["manual_review"] == 0.88


def test_policy_loosening_requires_human(policy_service):
    """Verify that loosening via service requires human actor and dwell."""
    policy = Policy(
        kind=PolicyKind.AUTONOMY,
        scope="investigate",
        params={"auto_approve": 0.80},
    )

    with pytest.raises(ValueError, match="requires a verified human actor"):
        policy_service.set_policy(
            policy,
            actor="agent",
            reason="Lower thresholds",
            direction=PolicyChangeDirection.LOOSEN,
            dwell_seconds=300,
        )
