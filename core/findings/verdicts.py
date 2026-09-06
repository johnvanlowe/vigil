"""Canonical verdict recording path for all human and automated actions on findings."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from sqlalchemy import select, update

from core.metrics.registry import get_metrics
from core.storage.connection import get_db_manager
from core.storage.ledger import append_agent_event
from core.storage.models.finding import Finding
from core.time import utcnow


class VerdictAction(str, Enum):
    """Canonical verdict actions allowed on findings."""

    CONFIRM = "confirm"
    DISMISS = "dismiss"
    ESCALATE = "escalate"
    EDIT_SEVERITY = "edit_severity"
    APPROVE = "approve"
    REJECT = "reject"


def record_verdict(
    finding_id: str,
    action: VerdictAction | str,
    actor: str,
    reason: Optional[str] = None,
    source: str = "ui",
    new_severity: Optional[str] = None,
    loglm_provenance: Optional[Dict[str, Any]] = None,
    attack_mapping: Optional[List[Dict[str, Any]]] = None,
    run_id: Optional[str] = None,
    session=None,
) -> Dict[str, Any]:
    """Record an immutable verdict for a finding, updating state and emitting a Ledger event.

    Invariants:
    - DISMISS and REJECT actions strictly require a non-empty reason.
    - Emits a schema v1 `verdict` event to `agent_events`.
    - Increments `vigil_verdict_total{action, source}` metric.
    """
    act = action.value if isinstance(action, VerdictAction) else str(action).lower()

    # Invariant: dismiss and reject require reason
    if act in (VerdictAction.DISMISS.value, VerdictAction.REJECT.value):
        if not reason or not reason.strip():
            raise ValueError(f"Action {act!r} strictly requires an explanatory reason.")

    # Status transition mapping
    status_map = {
        VerdictAction.CONFIRM.value: "confirmed",
        VerdictAction.DISMISS.value: "dismissed",
        VerdictAction.ESCALATE.value: "escalated",
        VerdictAction.APPROVE.value: "approved",
        VerdictAction.REJECT.value: "rejected",
    }
    new_status = status_map.get(act)

    now = utcnow()
    db = get_db_manager()
    if db._session_factory is None and session is None:
        try:
            db.initialize()
        except Exception:
            pass

    def _apply(s):
        try:
            stmt = select(Finding).where(Finding.finding_id == finding_id)
            finding = s.execute(stmt).scalars().first()
            if finding:
                if new_status:
                    finding.status = new_status
                if act == VerdictAction.EDIT_SEVERITY.value and new_severity:
                    finding.severity = new_severity
        except Exception:
            pass

    if session:
        _apply(session)
    elif db._session_factory is not None:
        try:
            with db.session_scope() as s:
                _apply(s)
        except Exception:
            pass

    # Increment metric
    try:
        get_metrics().verdict_total.labels(action=act, source=source).inc()
    except Exception:
        pass

    # Record event in Ledger
    effective_run_id = run_id or f"verdict-{finding_id}"
    payload = {
        "schema_version": 1,
        "finding_id": finding_id,
        "action": act,
        "actor": actor,
        "reason": reason,
        "source": source,
        "new_severity": new_severity,
        "loglm_provenance": loglm_provenance,
        "attack_mapping": attack_mapping,
        "timestamp": now.isoformat(),
    }

    append_agent_event(
        run_id=effective_run_id,
        kind="verdict",
        payload=payload,
        run_kind="compose",
        session=session,
    )

    return payload
