"""Author-or-defer checkpoint and resolution machinery for loop detection gaps.

Gated by Policy(kind=autonomy):
- Up-front policy auto-authors when confidence/tier exceeds threshold and records decision.
- Gaps requiring human review raise a GapCheckpoint answered by a GapResolution.
- Every choice is a recorded verdict event with action in {author, defer, accept_gap} and a reason.
- Promotion into the customer overlay is recorded as a human-granted or pre-authorized event.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Literal, Optional

from core.detections.candidates import CandidateStatus, DetectionCandidate
from core.policies.schema import Policy
from core.storage.ledger import append_agent_event
from core.time import utcnow

logger = logging.getLogger(__name__)


class GapAction(str, Enum):
    """Permitted resolution actions for an identified detection gap."""

    AUTHOR = "author"
    DEFER = "defer"
    ACCEPT_GAP = "accept_gap"


@dataclass
class GapCheckpoint:
    """A checkpoint raised during the loop requiring a disposition decision."""

    checkpoint_id: str
    gap_id: str
    technique_id: str
    environment_id: str
    action_name: str
    priority: str = "medium"
    status: str = "pending"  # pending, resolved
    created_at: str = field(default_factory=lambda: utcnow().isoformat())


@dataclass
class GapResolution:
    """Resolution of a GapCheckpoint."""

    checkpoint_id: str
    action: GapAction
    reason: str
    actor: str = "analyst"
    resolved_at: str = field(default_factory=lambda: utcnow().isoformat())


class LoopCheckpointManager:
    """Manages author-or-defer gates and resolutions."""

    def __init__(self, run_id: Optional[str] = None):
        self.run_id = run_id or f"loop-{utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}"
        self._checkpoints: Dict[str, GapCheckpoint] = {}

    def evaluate_gap_autonomy(
        self,
        gap: Dict[str, Any],
        autonomy_policy: Optional[Policy] = None,
        confidence: float = 0.85,
    ) -> tuple[bool, Optional[GapCheckpoint]]:
        """Evaluate if gap can be auto-authored under autonomy policy or needs checkpoint."""
        gap_id = gap.get("step_id") or gap.get("gap_id") or f"gap-{uuid.uuid4().hex[:6]}"
        tech_id = gap.get("technique_id") or gap.get("technique") or "T1059"
        env_id = gap.get("environment_id", "staging-range")
        name = gap.get("action_name") or f"Gap for {tech_id}"

        auto_author_threshold = 0.80
        if autonomy_policy and autonomy_policy.kind.value == "autonomy":
            auto_author_threshold = float(autonomy_policy.params.get("auto_author_threshold", 0.80))
            if autonomy_policy.params.get("force_review", False):
                auto_author_threshold = 1.1  # Force review

        if confidence >= auto_author_threshold:
            # Auto-author permitted: record verdict event
            self._record_verdict_event(
                gap_id=gap_id,
                action=GapAction.AUTHOR,
                reason=f"Auto-author policy threshold satisfied ({confidence:.2f} >= {auto_author_threshold:.2f})",
                actor="policy",
                environment_id=env_id,
            )
            return True, None

        # Autonomy threshold not met: raise checkpoint
        cp_id = f"cp-{gap_id}"
        checkpoint = GapCheckpoint(
            checkpoint_id=cp_id,
            gap_id=gap_id,
            technique_id=tech_id,
            environment_id=env_id,
            action_name=name,
            priority=gap.get("priority", "medium"),
        )
        self._checkpoints[cp_id] = checkpoint
        return False, checkpoint

    def resolve_checkpoint(
        self,
        checkpoint_id: str,
        action: GapAction,
        reason: str,
        actor: str = "analyst",
    ) -> GapResolution:
        """Resolve a raised checkpoint with action and mandatory reason."""
        if not reason or not reason.strip():
            raise ValueError(f"A non-empty reason is required to resolve gap checkpoint {checkpoint_id}")

        checkpoint = self._checkpoints.get(checkpoint_id)
        if not checkpoint:
            raise KeyError(f"Checkpoint {checkpoint_id} not found")

        checkpoint.status = "resolved"
        resolution = GapResolution(
            checkpoint_id=checkpoint_id,
            action=action,
            reason=reason.strip(),
            actor=actor,
        )

        self._record_verdict_event(
            gap_id=checkpoint.gap_id,
            action=action,
            reason=reason.strip(),
            actor=actor,
            environment_id=checkpoint.environment_id,
        )
        return resolution

    def promote_candidate(
        self,
        candidate: DetectionCandidate,
        actor: str,
        autonomy_policy: Optional[Policy] = None,
        overlay_path: Optional[str] = None,
    ) -> bool:
        """Promote validated candidate to overlay; requires human actor or pre-authorized policy."""
        is_pre_authorized = False
        if autonomy_policy and autonomy_policy.kind.value == "autonomy":
            is_pre_authorized = bool(autonomy_policy.params.get("pre_authorized_promotion", False))

        authorized_by = actor
        if not is_pre_authorized and (not actor or actor.lower() in ("system", "agent")):
            raise PermissionError(
                "Promotion to live overlay requires an authorized human actor or a pre-authorized autonomy policy."
            )

        candidate.status = CandidateStatus.PROMOTED
        candidate.promoted_at = utcnow()

        # Emit schema v1 promotion event
        payload = {
            "schema_version": 1,
            "candidate_id": candidate.candidate_id,
            "rule_name": candidate.rule_name,
            "format": candidate.format,
            "environment_id": candidate.environment_id,
            "authorized_by": authorized_by,
            "pre_authorized": is_pre_authorized,
            "overlay_path": overlay_path or f"overlay/{candidate.environment_id}/{candidate.candidate_id}.yml",
        }

        try:
            append_agent_event(
                run_id=self.run_id,
                kind="promotion",
                payload=payload,
                run_kind="compose",
            )
        except Exception as exc:
            logger.warning("Could not append promotion event to ledger: %s", exc)

        return True

    def _record_verdict_event(
        self,
        gap_id: str,
        action: GapAction,
        reason: str,
        actor: str,
        environment_id: str,
    ) -> int:
        """Record verdict event conforming to schema v1."""
        payload = {
            "schema_version": 1,
            "action": action.value,
            "source": "analyst" if actor != "policy" else "policy",
            "actor": actor,
            "reason": reason,
            "gap_id": gap_id,
            "environment_id": environment_id,
        }
        try:
            return append_agent_event(
                run_id=self.run_id,
                kind="verdict",
                payload=payload,
                run_kind="compose",
            )
        except Exception as exc:
            logger.warning("Could not append verdict event: %s", exc)
            return 0
