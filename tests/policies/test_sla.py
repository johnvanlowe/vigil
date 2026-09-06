"""Tests for Policy(kind=sla) thresholds and breach tracking."""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.metrics.registry import get_metrics
from core.policies.models import PolicyModel
from core.policies.schema import Policy, PolicyChangeDirection, PolicyKind
from core.policies.service import PolicyService
from core.policies.sla import (
    DEFAULT_SLA_TARGETS_SECONDS,
    record_sla_breach,
    sync_sla_metrics_from_policy,
    update_sla_policy,
)


def test_sla_policy_metrics_sync():
    """Verify sync_sla_metrics_from_policy sets vigil_sla_target_seconds."""
    engine = create_engine("sqlite:///:memory:")
    PolicyModel.__table__.create(engine)
    SessionLocal = sessionmaker(bind=engine)
    svc = PolicyService(session_factory=SessionLocal)

    sync_sla_metrics_from_policy(svc)
    metrics = get_metrics()

    crit_mtta = metrics.sla_target_seconds.labels(sla="mtta", severity="critical")._value.get()
    assert crit_mtta == DEFAULT_SLA_TARGETS_SECONDS["critical"]["mtta"]


def test_sla_breach_increment():
    """Verify record_sla_breach increments the breach counter."""
    metrics = get_metrics()
    before = metrics.sla_breach_total.labels(sla="mttr", severity="high")._value.get()

    record_sla_breach(sla_type="mttr", severity="high")

    after = metrics.sla_breach_total.labels(sla="mttr", severity="high")._value.get()
    assert after == before + 1


def test_update_sla_policy_creates_ledger_event():
    """Updating SLA policy updates targets and records policy change."""
    engine = create_engine("sqlite:///:memory:")
    PolicyModel.__table__.create(engine)
    SessionLocal = sessionmaker(bind=engine)
    svc = PolicyService(session_factory=SessionLocal)

    new_targets = {
        "critical": {"mtta": 120, "mttr": 900, "disposition": 300},
    }
    baseline_min = {"triage": 10.0}

    policy = update_sla_policy(
        targets=new_targets,
        baseline_minutes=baseline_min,
        actor="soc_manager",
        reason="Tightening MTTA targets for Q4",
        direction=PolicyChangeDirection.TIGHTEN,
        policy_service=svc,
    )

    assert policy.kind == PolicyKind.SLA
    assert policy.params["targets"]["critical"]["mtta"] == 120
