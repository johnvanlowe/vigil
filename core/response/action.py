"""Typed response action model with reversibility classes and idempotency."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, Optional, Set
from pydantic import BaseModel, Field

from core.policies.schema import PolicyKind
from core.policies.service import PolicyService


class ReversibilityClass(str, Enum):
    """Reversibility classification of an automated or approved response action."""

    REVERSIBLE = "reversible"
    IRREVERSIBLE = "irreversible"


class Action(BaseModel):
    """A proposed or executed response action."""

    action_id: str
    action_type: str
    target: str
    confidence: float = Field(ge=0.0, le=1.0)
    blast_radius: str = Field(..., description="Estimated scope or impact (e.g. single_host, subnet, tenant)")
    reversibility: ReversibilityClass
    rollback_plan: str
    idempotency_key: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    executed: bool = False
    execution_result: Optional[Dict[str, Any]] = None


class ActionExecutor:
    """Manages evaluation, approval routing, and idempotent execution of actions."""

    def __init__(self, policy_service: Optional[PolicyService] = None):
        self.policy_service = policy_service or PolicyService()
        self._executed_idempotency_keys: Set[str] = set()

    def requires_approval(self, action: Action) -> bool:
        """Determine whether an action must be routed to human approval.

        Invariants:
        - Irreversible actions ALWAYS route to human approval regardless of confidence.
        - Reversible actions follow Policy(kind=autonomy) auto-approval threshold.
        """
        if action.reversibility == ReversibilityClass.IRREVERSIBLE:
            return True

        thresholds = self.policy_service.get_autonomy_thresholds(scope=action.action_type)
        auto_approve_threshold = thresholds.get("auto_approve", 0.90)

        return action.confidence < auto_approve_threshold

    def execute_action(self, action: Action) -> Dict[str, Any]:
        """Execute the action, enforcing idempotency deduplication."""
        if action.idempotency_key in self._executed_idempotency_keys:
            return {
                "status": "deduplicated",
                "message": f"Action with idempotency key {action.idempotency_key!r} already executed.",
                "action_id": action.action_id,
            }

        self._executed_idempotency_keys.add(action.idempotency_key)
        action.executed = True
        result = {
            "status": "executed",
            "action_id": action.action_id,
            "action_type": action.action_type,
            "target": action.target,
        }
        action.execution_result = result
        return result
