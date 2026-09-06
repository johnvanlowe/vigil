"""CISO executive metrics calculation and reconciliation routines."""

from __future__ import annotations

from typing import Dict, Optional
from core.metrics.registry import get_metrics
from core.policies.schema import PolicyKind
from core.policies.service import PolicyService


DEFAULT_BASELINE_MINUTES = {
    "triage": 15.0,
    "investigation": 45.0,
    "response": 30.0,
}


def record_analyst_confirmation(stage: str = "triage", overturned: bool = False) -> None:
    """Record human confirmation or overturn of an agent decision.

    Note: A human confirming an agent output counts as agent work plus one confirmation event.
    """
    metrics = get_metrics()
    try:
        if overturned:
            metrics.agent_dispositions_overturned_total.labels(stage=stage).inc()
        else:
            metrics.agent_dispositions_confirmed_total.labels(stage=stage).inc()
    except Exception:
        pass


def update_hours_returned_estimates(
    completed_agent_tasks: Dict[str, int],
    policy_service: Optional[PolicyService] = None,
) -> Dict[str, float]:
    """Compute and export vigil_hours_returned_estimate based on baseline minutes."""
    svc = policy_service or PolicyService()
    sla_policy = svc.get_policy(PolicyKind.SLA, scope="*")

    baseline_minutes = DEFAULT_BASELINE_MINUTES
    if sla_policy and "baseline_minutes" in sla_policy.params:
        baseline_minutes = {**DEFAULT_BASELINE_MINUTES, **sla_policy.params["baseline_minutes"]}

    metrics = get_metrics()
    hours_returned = {}

    for stage, count in completed_agent_tasks.items():
        minutes_per_task = baseline_minutes.get(stage, 15.0)
        total_hours = (count * minutes_per_task) / 60.0
        hours_returned[stage] = total_hours
        try:
            metrics.hours_returned_estimate.labels(stage=stage).set(total_hours)
        except Exception:
            pass

    return hours_returned
