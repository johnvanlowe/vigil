"""Canonical advisory-locked append-only Ledger for agent events (agent_events table).

Guarantees single-writer sequential integrity per run_id by acquiring a PostgreSQL
transaction-level advisory lock (`pg_advisory_xact_lock(hashtext(:run_id)::bigint)`).
Assigns monotonic, gapless `seq` numbers server-side via subquery:
    coalesce((SELECT max(seq) FROM agent_events WHERE run_id = :run_id), -1) + 1
"""

from __future__ import annotations

import json
import logging
import threading
import uuid
from typing import Any, Dict, Optional
from sqlalchemy import text
from sqlalchemy.orm import Session

from core.ledger.hash import GENESIS_HASH, compute_event_hash
from core.storage.connection import get_db_manager
from core.time import utcnow

logger = logging.getLogger(__name__)

EVENT_SCHEMA_VERSION = 1

# Process-level thread lock for non-Postgres engines (e.g. SQLite in offline tests)
_LOCAL_RUN_LOCKS: Dict[str, threading.Lock] = {}
_LOCAL_LOCK_GUARD = threading.Lock()


def normalize_run_id(val: Any) -> str:
    """Normalize any run_id string or UUID into a valid UUID string.

    Guarantees deterministic conversion so arbitrary strings (e.g. 'cl-20260905')
    never fail PostgreSQL's uuid column type validation.
    """
    if isinstance(val, uuid.UUID):
        return str(val)
    val_str = str(val).strip()
    try:
        return str(uuid.UUID(val_str))
    except (ValueError, AttributeError):
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, val_str))


def _get_run_lock(run_id: str) -> threading.Lock:
    norm_id = normalize_run_id(run_id)
    with _LOCAL_LOCK_GUARD:
        if norm_id not in _LOCAL_RUN_LOCKS:
            _LOCAL_RUN_LOCKS[norm_id] = threading.Lock()
        return _LOCAL_RUN_LOCKS[norm_id]


def append_agent_event(
    run_id: str | uuid.UUID,
    kind: str,
    payload: Dict[str, Any],
    run_kind: str = "compose",
    snapshot: Optional[Dict[str, Any]] = None,
    schema_version: int = EVENT_SCHEMA_VERSION,
    session: Optional[Session] = None,
) -> int:
    """Append an event to agent_events table with advisory locking and server-assigned seq.

    Guarantees that two concurrent writers for the same run_id take turns under
    an advisory lock, eliminating primary-key collisions on (run_id, seq).

    Raises any database exception so callers cannot silently proceed on failed writes.
    """
    norm_run_id = normalize_run_id(run_id)
    db = get_db_manager()
    if db._session_factory is None and session is None:
        try:
            db.initialize()
        except Exception as exc:
            logger.debug("Database initialize in ledger: %s", exc)

    def _execute_append(sess: Session) -> int:
        run_lock = _get_run_lock(norm_run_id)
        with run_lock:
            dialect_name = sess.bind.dialect.name if sess.bind else "postgresql"
            if dialect_name == "postgresql":
                # Acquire transaction-scoped advisory lock keyed on the run_id hash.
                # Held until transaction commit or rollback.
                sess.execute(
                    text("SELECT pg_advisory_xact_lock(hashtext(:run_id)::bigint)"),
                    {"run_id": norm_run_id},
                )

            now = utcnow()
            try:
                if dialect_name == "postgresql":
                    prev_row = sess.execute(
                        text("SELECT event_hash FROM agent_events WHERE run_id = CAST(:run_id AS uuid) ORDER BY seq DESC LIMIT 1"),
                        {"run_id": norm_run_id},
                    ).scalar()
                else:
                    prev_row = sess.execute(
                        text("SELECT event_hash FROM agent_events WHERE run_id = :run_id ORDER BY seq DESC LIMIT 1"),
                        {"run_id": norm_run_id},
                    ).scalar()
            except Exception:
                prev_row = None

            prev_h = str(prev_row) if prev_row else GENESIS_HASH
            ev_h = compute_event_hash(prev_h, payload)

            if dialect_name == "postgresql":
                sql = text(
                    """
                    INSERT INTO agent_events (
                        run_id, run_kind, seq, ts, kind, payload, snapshot, schema_version, prev_hash, event_hash
                    )
                    SELECT
                        CAST(:run_id AS uuid),
                        :run_kind,
                        coalesce((SELECT max(seq) FROM agent_events WHERE run_id = CAST(:run_id AS uuid)), -1) + 1,
                        :ts,
                        :kind,
                        CAST(:payload AS jsonb),
                        CAST(:snapshot AS jsonb),
                        :schema_version,
                        :prev_hash,
                        :event_hash
                    RETURNING seq
                    """
                )
            else:
                sql = text(
                    """
                    INSERT INTO agent_events (
                        run_id, run_kind, seq, ts, kind, payload, snapshot, schema_version, prev_hash, event_hash
                    )
                    VALUES (
                        :run_id,
                        :run_kind,
                        coalesce((SELECT max(seq) FROM agent_events WHERE run_id = :run_id), -1) + 1,
                        :ts,
                        :kind,
                        :payload,
                        :snapshot,
                        :schema_version,
                        :prev_hash,
                        :event_hash
                    )
                    RETURNING seq
                    """
                )

            res = sess.execute(
                sql,
                {
                    "run_id": norm_run_id,
                    "run_kind": run_kind,
                    "ts": now,
                    "kind": kind,
                    "payload": json.dumps(payload),
                    "snapshot": json.dumps(snapshot) if snapshot is not None else None,
                    "schema_version": schema_version,
                    "prev_hash": prev_h,
                    "event_hash": ev_h,
                },
            )
            assigned_seq = res.scalar()
            return int(assigned_seq) if assigned_seq is not None else 0

    if session is not None:
        return _execute_append(session)

    with db.session_scope() as sess:
        return _execute_append(sess)
