"""Unified Policy schema and PolicyChange event models for Vigil governance.

Ratchet Invariant:
Any modification where direction is "loosen" (e.g. lowering approval thresholds,
increasing budget caps, widening autonomy scope, or relaxing offensive safety)
strictly requires a human actor and records a mandatory dwell period (dwell_seconds).
Automated or agentic callers are prohibited from loosening governance policies.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field

from core.time import utcnow


class PolicyKind(str, Enum):
    """Enumeration of policy governance kinds."""

    AUTONOMY = "autonomy"
    BUDGET = "budget"
    SUPPRESSION = "suppression"
    OFFENSIVE = "offensive"
    SLA = "sla"


class PolicyChangeDirection(str, Enum):
    """Direction of policy modification."""

    TIGHTEN = "tighten"
    LOOSEN = "loosen"


class Policy(BaseModel):
    """Core governance policy model in Vigil."""

    id: str = Field(default_factory=lambda: f"pol-{uuid.uuid4().hex[:12]}")
    kind: PolicyKind
    scope: str = Field(
        ...,
        description="Target scope: action class, run_kind, match pattern, or environment_id",
    )
    params: Dict[str, Any] = Field(default_factory=dict)
    ttl: Optional[int] = Field(
        default=None,
        description="Time-to-live in seconds, after which policy expires",
    )
    promoted_by: Optional[str] = Field(
        default=None,
        description="Actor or authority who approved/promoted this policy",
    )
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: Optional[datetime] = None


class PolicyChange(BaseModel):
    """Ledger event payload emitted on policy creation or modification."""

    schema_version: int = 1
    policy_id: str
    kind: PolicyKind
    direction: PolicyChangeDirection
    actor: str
    reason: str
    dwell_seconds: Optional[int] = None
    previous_params: Optional[Dict[str, Any]] = None
    new_params: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=utcnow)

    def validate_loosen_ratchet(self) -> None:
        """Enforce ratchet: loosen requires human actor and dwell."""
        if self.direction == PolicyChangeDirection.LOOSEN:
            if not self.actor or self.actor.lower() in ("agent", "system", "auto"):
                raise ValueError("Policy loosening requires a verified human actor.")
            if self.dwell_seconds is None or self.dwell_seconds <= 0:
                raise ValueError("Policy loosening requires recording a positive dwell_seconds.")
