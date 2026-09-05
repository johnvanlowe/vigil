"""Author-or-defer decision policy and promotion lifecycle.

Implements the Demote-Yourself-Only house rule:
1. The system proposes freely and validates rigorously.
2. An operator decides author vs defer vs accept gap (either up front via policy
   or in the loop via approval checkpoints).
3. Promotion into the live detection set requires explicit human approval or
   a pre-authorized high-confidence policy.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from core.detections.candidate import CandidateStatus, DetectionCandidate
from core.response.approval_service import ActionStatus, ActionType, ApprovalService
from core.response.checkpoints import raise_for_checkpoint
from core.storage.connection import get_db_manager
from core.time import utcnow

logger = logging.getLogger(__name__)


class GapDecision(str, Enum):
    """Action chosen for an identified detection gap."""

    AUTHOR_NOW = "author_now"
    DEFER = "defer"
    ACCEPT_GAP = "accept_gap"


@dataclass
class AuthoringPolicy:
    """Governance policy controlling autonomy in detection authoring and promotion."""

    policy_id: str = "default_authoring_policy"
    auto_author_min_severity: str = "high"
    min_confidence: float = 0.90
    review_threshold: float = 0.85
    default_action: str = "ask"  # "ask", "auto_author", "defer"
    require_human_promotion: bool = True

    def should_auto_author(self, gap_priority: str, confidence: float) -> bool:
        """Determine whether a gap should be automatically authored based on policy."""
        if self.default_action == "auto_author":
            if confidence >= self.min_confidence:
                return True
            if gap_priority.lower() == "high" and confidence >= self.review_threshold:
                return True
        return False


class GapTriageService:
    """Manages gap triage checkpoints and promotion to live detection set."""

    def __init__(self, run_id: str, policy: Optional[AuthoringPolicy] = None):
        self.run_id = run_id
        self.policy = policy or AuthoringPolicy()
        self.decisions: Dict[str, Dict[str, Any]] = {}

    def triage_gap(
        self,
        gap: Dict[str, Any],
        confidence: float = 0.92,
        phase_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Evaluate a gap against policy: auto-author or raise a checkpoint for human choice."""
        step_id = gap.get("step_id", "step-unknown")
        technique_id = gap.get("technique_id", "unknown")
        priority = gap.get("priority", "medium")

        if self.policy.should_auto_author(priority, confidence):
            decision_record = {
                "step_id": step_id,
                "technique_id": technique_id,
                "decision": GapDecision.AUTHOR_NOW.value,
                "confidence": confidence,
                "reason": f"Auto-authored under policy: confidence {confidence:.2f} >= threshold",
                "decided_by": "policy_auto",
                "timestamp": utcnow().isoformat(),
            }
            self.decisions[step_id] = decision_record
            self.append_decision_to_ledger(decision_record)
            return decision_record

        # Raise an in-loop approval checkpoint for operator choice
        checkpoint_id = f"chk-gap-{step_id}"
        raise_for_checkpoint(
            run_id=self.run_id,
            checkpoint_id=checkpoint_id,
            title=f"Gap Triage: Author detection for {technique_id}?",
            description=(
                f"Attack step {step_id} probing {technique_id} ({gap.get('action_name', 'action')}) was not caught "
                "by current rules. Choose whether to author a behavioral rule now, defer, or accept this gap."
            ),
            reason="Operator triage required before authoring new detection rule.",
            parameters={
                "gap": gap,
                "confidence": confidence,
                "available_actions": [
                    GapDecision.AUTHOR_NOW.value,
                    GapDecision.DEFER.value,
                    GapDecision.ACCEPT_GAP.value,
                ],
            },
            phase_id=phase_id,
        )

        decision_record = {
            "step_id": step_id,
            "technique_id": technique_id,
            "decision": "pending_operator_choice",
            "checkpoint_id": checkpoint_id,
            "timestamp": utcnow().isoformat(),
        }
        self.decisions[step_id] = decision_record
        return decision_record

    def record_operator_resolution(
        self,
        step_id: str,
        decision: GapDecision,
        reason: str,
        resolved_by: str = "operator",
    ) -> Dict[str, Any]:
        """Record human operator resolution to a gap triage checkpoint."""
        record = {
            "step_id": step_id,
            "decision": decision.value,
            "reason": reason,
            "decided_by": resolved_by,
            "timestamp": utcnow().isoformat(),
        }
        self.decisions[step_id] = record
        self.append_decision_to_ledger(record)
        return record

    def promote_candidate(
        self,
        candidate: DetectionCandidate,
        authorized_by: str,
        pre_authorized: bool = False,
    ) -> bool:
        """Promote a validated candidate into the live detection repository."""
        # Validation prerequisite: must have passed validation harness
        if not candidate.validation or not candidate.validation.is_valid:
            logger.warning(
                "Promotion refused: candidate %s has not passed the validation harness.",
                candidate.candidate_id,
            )
            return False

        if self.policy.require_human_promotion and not pre_authorized:
            # Check for authorized actor
            if not authorized_by or authorized_by == "agent":
                logger.warning(
                    "Promotion refused: Demote-yourself-only rule requires human operator approval."
                )
                return False

        candidate.status = CandidateStatus.PROMOTED
        candidate.promoted_at = utcnow()

        promotion_event = {
            "candidate_id": candidate.candidate_id,
            "technique_id": candidate.gap_technique_id,
            "name": candidate.name,
            "format": candidate.format,
            "promoted_by": authorized_by,
            "promoted_at": candidate.promoted_at.isoformat(),
            "target_environment": candidate.target_environment,
        }

        self.append_promotion_to_ledger(promotion_event)
        logger.info("Candidate %s successfully promoted to live library by %s", candidate.candidate_id, authorized_by)
        return True

    def append_decision_to_ledger(self, record: Dict[str, Any]) -> None:
        """Record gap triage decision to agent_events."""
        self._append_ledger_event("gap_triage_decision", record)

    def append_promotion_to_ledger(self, record: Dict[str, Any]) -> None:
        """Record promotion event to agent_events."""
        self._append_ledger_event("detection_promotion", record)

    def _append_ledger_event(self, kind: str, payload: Dict[str, Any]) -> None:
        now = utcnow()
        try:
            db = get_db_manager()
            with db.session_scope() as session:
                query = session.execute(
                    """
                    SELECT COALESCE(MAX(seq), 0) + 1 FROM agent_events
                    WHERE run_id = CAST(:run_id AS uuid)
                    """,
                    {"run_id": self.run_id},
                )
                next_seq = query.scalar() or 1

                session.execute(
                    """
                    INSERT INTO agent_events (
                        run_id, seq, ts, run_kind, kind, payload, schema_version
                    ) VALUES (
                        CAST(:run_id AS uuid), :seq, :ts, :run_kind, :kind, CAST(:payload AS jsonb), :schema_version
                    )
                    """,
                    {
                        "run_id": self.run_id,
                        "seq": next_seq,
                        "ts": now,
                        "run_kind": "compose",
                        "kind": kind,
                        "payload": json.dumps(payload),
                        "schema_version": 1,
                    },
                )
        except Exception as exc:
            logger.warning("Could not write %s to agent_events table: %s", kind, exc)
