"""Tests for CISO metrics series, work share, and hours returned estimates."""

from core.findings.lifecycle import record_stage_completed
from core.metrics.ciso import record_analyst_confirmation, update_hours_returned_estimates
from core.metrics.registry import get_metrics


def test_stage_completed_records_work_and_actor():
    """Verify that stage_completed increments vigil_work_total with actor."""
    metrics = get_metrics()
    before = metrics.work_total.labels(stage="triage", actor="agent")._value.get()

    res = record_stage_completed(
        finding_id="f-ciso-1",
        stage="triage",
        actor="agent",
        elapsed_seconds=42.0,
        severity="high",
    )

    assert res["actor"] == "agent"
    after = metrics.work_total.labels(stage="triage", actor="agent")._value.get()
    assert after == before + 1


def test_analyst_confirmation_and_overturn():
    """Verify analyst confirmations and overturns are counted independently."""
    metrics = get_metrics()
    before_conf = metrics.agent_dispositions_confirmed_total.labels(stage="investigate")._value.get()
    before_over = metrics.agent_dispositions_overturned_total.labels(stage="investigate")._value.get()

    record_analyst_confirmation(stage="investigate", overturned=False)
    record_analyst_confirmation(stage="investigate", overturned=True)

    after_conf = metrics.agent_dispositions_confirmed_total.labels(stage="investigate")._value.get()
    after_over = metrics.agent_dispositions_overturned_total.labels(stage="investigate")._value.get()

    assert after_conf == before_conf + 1
    assert after_over == before_over + 1


def test_hours_returned_estimation():
    """Verify hours returned calculation based on baseline minutes."""
    agent_tasks = {
        "triage": 60,       # 60 tasks * 15 min = 900 min = 15 hours
        "investigation": 20, # 20 tasks * 45 min = 900 min = 15 hours
    }
    estimates = update_hours_returned_estimates(agent_tasks)
    assert estimates["triage"] == 15.0
    assert estimates["investigation"] == 15.0
