"""CLI commands for Vigil Ledger verification and timeline visualization."""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, List, Optional
from sqlalchemy import text

from core.ledger.hash import verify_chain
from core.storage.connection import get_db_manager
from core.storage.ledger import normalize_run_id


def verify_ledger(run_id: Optional[str] = None) -> Dict[str, Any]:
    """Walk and verify the hash chain of agent_events for a specific run or all runs.

    Returns summary dictionary {total_events, runs_checked, valid, error}.
    """
    db = get_db_manager()
    with db.session_scope() as session:
        dialect = session.bind.dialect.name if session.bind else "postgresql"
        if run_id:
            norm_id = normalize_run_id(run_id)
            if dialect == "postgresql":
                sql = text(
                    "SELECT seq, prev_hash, event_hash, payload FROM agent_events WHERE run_id = CAST(:run_id AS uuid) ORDER BY seq ASC"
                )
            else:
                sql = text(
                    "SELECT seq, prev_hash, event_hash, payload FROM agent_events WHERE run_id = :run_id ORDER BY seq ASC"
                )
            rows = session.execute(sql, {"run_id": norm_id}).fetchall()
            events = [
                {
                    "seq": r[0],
                    "prev_hash": r[1],
                    "event_hash": r[2],
                    "payload": json.loads(r[3]) if isinstance(r[3], str) else r[3],
                }
                for r in rows
            ]
            valid, err = verify_chain(events)
            return {
                "total_events": len(events),
                "runs_checked": 1,
                "valid": valid,
                "error": err,
            }

        # Global verification across all runs
        runs_sql = text("SELECT DISTINCT run_id FROM agent_events")
        run_ids = [str(r[0]) for r in session.execute(runs_sql).fetchall()]
        total_events = 0
        for r_id in run_ids:
            if dialect == "postgresql":
                sql = text(
                    "SELECT seq, prev_hash, event_hash, payload FROM agent_events WHERE run_id = CAST(:run_id AS uuid) ORDER BY seq ASC"
                )
            else:
                sql = text(
                    "SELECT seq, prev_hash, event_hash, payload FROM agent_events WHERE run_id = :run_id ORDER BY seq ASC"
                )
            rows = session.execute(sql, {"run_id": r_id}).fetchall()
            events = [
                {
                    "seq": r[0],
                    "prev_hash": r[1],
                    "event_hash": r[2],
                    "payload": json.loads(r[3]) if isinstance(r[3], str) else r[3],
                }
                for r in rows
            ]
            total_events += len(events)
            valid, err = verify_chain(events)
            if not valid:
                return {
                    "total_events": total_events,
                    "runs_checked": len(run_ids),
                    "valid": False,
                    "tampered_run_id": r_id,
                    "error": err,
                }

        return {
            "total_events": total_events,
            "runs_checked": len(run_ids),
            "valid": True,
            "error": None,
        }


def show_ledger_timeline(run_id: str) -> List[Dict[str, Any]]:
    """Render the chronological timeline of events for a run."""
    db = get_db_manager()
    norm_id = normalize_run_id(run_id)
    with db.session_scope() as session:
        dialect = session.bind.dialect.name if session.bind else "postgresql"
        if dialect == "postgresql":
            sql = text(
                "SELECT seq, ts, kind, payload, event_hash FROM agent_events WHERE run_id = CAST(:run_id AS uuid) ORDER BY seq ASC"
            )
        else:
            sql = text(
                "SELECT seq, ts, kind, payload, event_hash FROM agent_events WHERE run_id = :run_id ORDER BY seq ASC"
            )
        rows = session.execute(sql, {"run_id": norm_id}).fetchall()
        timeline = []
        for r in rows:
            payload = json.loads(r[3]) if isinstance(r[3], str) else r[3]
            timeline.append(
                {
                    "seq": r[0],
                    "timestamp": r[1].isoformat() if hasattr(r[1], "isoformat") else str(r[1]),
                    "kind": r[2],
                    "payload": payload,
                    "event_hash": r[4],
                }
            )
        return timeline
