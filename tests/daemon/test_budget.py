"""Tests for daemon Policy(kind=budget) enforcement and fail-static posture."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.metrics.registry import get_metrics
from core.policies.models import PolicyModel
from core.policies.schema import Policy, PolicyKind
from core.policies.service import PolicyService
from services.daemon.budget import DaemonBudgetEnforcer


def test_budget_enforcer_allows_within_budget():
    """Execution within budget cap is permitted."""
    engine = create_engine("sqlite:///:memory:")
    PolicyModel.__table__.create(engine)
    SessionLocal = sessionmaker(bind=engine)
    svc = PolicyService(session_factory=SessionLocal)

    enforcer = DaemonBudgetEnforcer(policy_service=svc)
    allowed, reason = enforcer.check_and_enforce(
        run_id="run-b-1",
        run_kind="compose",
        current_spend_usd=1.50,
    )
    assert allowed is True
    assert reason is None


def test_budget_enforcer_halts_on_exhaustion_and_increments_metric():
    """Execution exceeding budget cap halts and increments vigil_budget_exhausted_total."""
    engine = create_engine("sqlite:///:memory:")
    PolicyModel.__table__.create(engine)
    SessionLocal = sessionmaker(bind=engine)
    svc = PolicyService(session_factory=SessionLocal)

    # Set strict policy cap of $2.00
    policy = Policy(
        kind=PolicyKind.BUDGET,
        scope="triage",
        params={"max_cost_usd": 2.0},
    )
    svc.set_policy(policy, actor="sec_admin", reason="Set triage budget limit")

    enforcer = DaemonBudgetEnforcer(policy_service=svc)
    metrics = get_metrics()
    before_count = metrics.budget_exhausted_total.labels(run_kind="triage")._value.get()

    allowed, reason = enforcer.check_and_enforce(
        run_id="run-b-exhaust",
        run_kind="triage",
        current_spend_usd=2.05,
    )

    assert allowed is False
    assert "Budget cap reached" in reason

    after_count = metrics.budget_exhausted_total.labels(run_kind="triage")._value.get()
    assert after_count == before_count + 1
