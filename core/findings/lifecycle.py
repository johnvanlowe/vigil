"""Finding lifecycle progression emitting stage_completed events and CISO metrics."""

from __future__ import annotations

from typing import Any, Dict, Literal, Optional
from core.metrics.registry import get_metrics
from core.storage.ledger import append_agent_event
from core.time import utcnow


ActorType = Literal["agent", "human", "policy"]


def record_stage_completed(
    finding_id: str,
    stage: str,
    actor: ActorType,
    elapsed_seconds: float = 0.0,
    severity: str = "medium",
    run_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Emit stage_completed event and increment vigil_work_total.

    Key rule: A human confirming an agent output counts as agent work plus one
    confirmation event, never as human work.
    """
    effective_actor = actor
    metrics = get_metrics()

    # Increment work total
    try:
        metrics.work_total.labels(stage=stage, actor=effective_actor).inc()
    except Exception:
        pass

    effective_run_id = run_id or f"stage-{finding_id}-{stage}"
    payload = {
        "schema_version": 1,
        "action": "stage_completed",
        "finding_id": finding_id,
        "stage": stage,
        "actor": effective_actor,
        "elapsed_seconds": elapsed_seconds,
        "severity": severity,
        "metadata": metadata or {},
        "timestamp": utcnow().isoformat(),
    }

    try:
        append_agent_event(
            run_id=effective_run_id,
            kind="agent_event",
            payload=payload,
            run_kind="compose",
        )
    except Exception:
        pass

    return payload
