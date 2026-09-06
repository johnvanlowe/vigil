"""SLA policy management and metric threshold export."""

from __future__ import annotations

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field

from core.metrics.registry import get_metrics
from core.policies.schema import Policy, PolicyChangeDirection, PolicyKind
from core.policies.service import PolicyService


DEFAULT_SLA_TARGETS_SECONDS = {
    "critical": {"mtta": 300, "mttr": 1800, "disposition": 600},
    "high": {"mtta": 900, "mttr": 3600, "disposition": 1800},
    "medium": {"mtta": 3600, "mttr": 14400, "disposition": 7200},
    "low": {"mtta": 14400, "mttr": 86400, "disposition": 28800},
}


def sync_sla_metrics_from_policy(policy_service: Optional[PolicyService] = None) -> None:
    """Read active Policy(kind=sla) and export vigil_sla_target_seconds gauges."""
    svc = policy_service or PolicyService()
    policy = svc.get_policy(PolicyKind.SLA, scope="*")
    targets = DEFAULT_SLA_TARGETS_SECONDS

    if policy and "targets" in policy.params:
        targets = policy.params["targets"]

    metrics = get_metrics()
    for severity, sla_dict in targets.items():
        if isinstance(sla_dict, dict):
            for sla_type, val in sla_dict.items():
                try:
                    metrics.sla_target_seconds.labels(sla=sla_type, severity=severity).set(float(val))
                except Exception:
                    pass


def record_sla_breach(sla_type: str, severity: str) -> None:
    """Increment vigil_sla_breach_total when an SLA target is violated."""
    metrics = get_metrics()
    try:
        metrics.sla_breach_total.labels(sla=sla_type, severity=severity).inc()
    except Exception:
        pass


def update_sla_policy(
    targets: Dict[str, Dict[str, float]],
    baseline_minutes: Dict[str, float],
    actor: str,
    reason: str,
    direction: PolicyChangeDirection = PolicyChangeDirection.TIGHTEN,
    policy_service: Optional[PolicyService] = None,
) -> Policy:
    """Update SLA policy targets, appending a policy_change event to the Ledger."""
    svc = policy_service or PolicyService()
    policy = Policy(
        kind=PolicyKind.SLA,
        scope="*",
        params={"targets": targets, "baseline_minutes": baseline_minutes},
        promoted_by=actor,
    )
    res = svc.set_policy(
        policy=policy,
        actor=actor,
        reason=reason,
        direction=direction,
        dwell_seconds=600 if direction == PolicyChangeDirection.LOOSEN else None,
    )
    sync_sla_metrics_from_policy(svc)
    return res
