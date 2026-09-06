"""Policy service for storing, querying, and auditing governance policies."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from sqlalchemy import select

from core.policies.models import PolicyModel
from core.policies.schema import (
    Policy,
    PolicyChange,
    PolicyChangeDirection,
    PolicyKind,
)
from core.storage.connection import get_db_manager
from core.storage.ledger import append_agent_event
from core.time import utcnow

logger = logging.getLogger(__name__)

# Default approval thresholds migrated from legacy settings
DEFAULT_AUTONOMY_THRESHOLDS = {
    "auto_approve": 0.90,
    "manual_review": 0.85,
}


from contextlib import contextmanager


class PolicyService:
    """Service managing runtime policies and Ledger audit logging."""

    def __init__(self, db=None, session_factory=None):
        self._db = db or get_db_manager()
        self._session_factory = session_factory

    @contextmanager
    def session_scope(self):
        if self._session_factory:
            sess = self._session_factory()
            try:
                yield sess
                sess.commit()
            except Exception:
                sess.rollback()
                raise
            finally:
                sess.close()
        else:
            if self._db._session_factory is None:
                try:
                    self._db.initialize()
                except Exception:
                    pass
            with self._db.session_scope() as sess:
                yield sess

    def list_policies(self, kind: Optional[PolicyKind | str] = None) -> List[Policy]:
        """Fetch all active policies, optionally filtered by kind."""
        with self.session_scope() as session:
            stmt = select(PolicyModel)
            if kind is not None:
                kind_str = kind.value if isinstance(kind, PolicyKind) else str(kind)
                stmt = stmt.where(PolicyModel.kind == kind_str)
            stmt = stmt.order_by(PolicyModel.created_at.desc())
            rows = session.execute(stmt).scalars().all()
            return [
                Policy(
                    id=r.id,
                    kind=PolicyKind(r.kind),
                    scope=r.scope,
                    params=r.params or {},
                    ttl=r.ttl,
                    promoted_by=r.promoted_by,
                    created_at=r.created_at,
                    updated_at=r.updated_at,
                )
                for r in rows
            ]

    def get_policy(self, kind: PolicyKind | str, scope: str = "*") -> Optional[Policy]:
        """Fetch active policy by kind and scope, with fallback to wildcard scope."""
        kind_str = kind.value if isinstance(kind, PolicyKind) else str(kind)
        with self.session_scope() as session:
            stmt = (
                select(PolicyModel)
                .where(PolicyModel.kind == kind_str)
                .where(PolicyModel.scope.in_([scope, "*"]))
                .order_by(PolicyModel.scope.desc(), PolicyModel.created_at.desc())
            )
            row = session.execute(stmt).scalars().first()
            if not row:
                return None
            return Policy(
                id=row.id,
                kind=PolicyKind(row.kind),
                scope=row.scope,
                params=row.params or {},
                ttl=row.ttl,
                promoted_by=row.promoted_by,
                created_at=row.created_at,
                updated_at=row.updated_at,
            )

    def set_policy(
        self,
        policy: Policy,
        actor: str,
        reason: str,
        direction: PolicyChangeDirection = PolicyChangeDirection.TIGHTEN,
        dwell_seconds: Optional[int] = None,
        run_id: Optional[str] = None,
    ) -> Policy:
        """Create or update a policy, validating loosen ratchets and logging to the Ledger."""
        change = PolicyChange(
            policy_id=policy.id,
            kind=policy.kind,
            direction=direction,
            actor=actor,
            reason=reason,
            dwell_seconds=dwell_seconds,
            new_params=policy.params,
        )
        # Enforce loosen ratchet
        change.validate_loosen_ratchet()

        now = utcnow()
        with self.session_scope() as session:
            existing = session.get(PolicyModel, policy.id)
            prev_params = existing.params if existing else None
            change.previous_params = prev_params

            if existing:
                existing.kind = policy.kind.value
                existing.scope = policy.scope
                existing.params = policy.params
                existing.ttl = policy.ttl
                existing.promoted_by = policy.promoted_by
                existing.updated_at = now
            else:
                new_row = PolicyModel(
                    id=policy.id,
                    kind=policy.kind.value,
                    scope=policy.scope,
                    params=policy.params,
                    ttl=policy.ttl,
                    promoted_by=policy.promoted_by,
                    created_at=now,
                )
                session.add(new_row)

        # Audit to Ledger
        effective_run_id = run_id or f"policy-change-{policy.id}"
        append_agent_event(
            run_id=effective_run_id,
            kind="policy_change",
            payload={
                "schema_version": 1,
                "policy_id": policy.id,
                "kind": policy.kind.value,
                "direction": direction.value,
                "actor": actor,
                "reason": reason,
                "dwell_seconds": dwell_seconds,
                "previous_params": prev_params,
                "new_params": policy.params,
            },
            run_kind="compose",
        )

        return policy

    def get_autonomy_thresholds(self, scope: str = "*") -> Dict[str, float]:
        """Retrieve approval thresholds from policy, falling back to 0.90 / 0.85 defaults."""
        policy = self.get_policy(PolicyKind.AUTONOMY, scope=scope)
        if policy and policy.params:
            return {
                "auto_approve": float(policy.params.get("auto_approve", DEFAULT_AUTONOMY_THRESHOLDS["auto_approve"])),
                "manual_review": float(policy.params.get("manual_review", DEFAULT_AUTONOMY_THRESHOLDS["manual_review"])),
            }
        return dict(DEFAULT_AUTONOMY_THRESHOLDS)
