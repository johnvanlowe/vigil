"""Suppression policy management and finding evaluation."""

from __future__ import annotations

import fnmatch
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from core.metrics.registry import get_metrics
from core.policies.schema import Policy, PolicyChangeDirection, PolicyKind
from core.policies.service import PolicyService
from core.time import utcnow


def promote_to_suppression_policy(
    match_pattern: str,
    reason: str,
    ttl_seconds: int,
    promoted_by: str,
    service: Optional[PolicyService] = None,
) -> Policy:
    """Promote a recurrent dismissal candidate into an active suppression policy with a TTL."""
    svc = service or PolicyService()
    policy = Policy(
        kind=PolicyKind.SUPPRESSION,
        scope=match_pattern,
        params={"reason": reason},
        ttl=ttl_seconds,
        promoted_by=promoted_by,
    )

    return svc.set_policy(
        policy=policy,
        actor=promoted_by,
        reason=f"Promoted dismissal suppression: {reason}",
        direction=PolicyChangeDirection.TIGHTEN,
        dwell_seconds=None,
    )


def is_suppressed(
    finding_data: Dict[str, Any],
    active_policies: Optional[List[Policy]] = None,
    service: Optional[PolicyService] = None,
) -> Tuple[bool, Optional[str]]:
    """Check if a finding matches an active, unexpired suppression policy.

    If suppressed, increments vigil_suppressed_findings_total metric.
    Returns (is_suppressed, matching_policy_id).
    """
    now = utcnow()
    policies = active_policies
    if policies is None:
        svc = service or PolicyService()
        policies = svc.list_policies(PolicyKind.SUPPRESSION)

    target_fields = [
        str(finding_data.get("description", "")),
        str(finding_data.get("rule_name", "")),
        str(finding_data.get("source", "")),
        str(finding_data.get("cluster_id", "")),
    ]

    for p in policies:
        if not p or p.kind != PolicyKind.SUPPRESSION:
            continue

        # Check expiration
        if p.ttl and p.created_at:
            expiry = p.created_at + timedelta(seconds=p.ttl)
            if now > expiry:
                continue

        pattern = p.scope
        # Match pattern against any target field
        for field_val in target_fields:
            if pattern == "*" or fnmatch.fnmatch(field_val.lower(), pattern.lower()) or pattern.lower() in field_val.lower():
                try:
                    get_metrics().suppressed_findings_total.labels(match=pattern).inc()
                except Exception:
                    pass
                return True, p.id

    return False, None
