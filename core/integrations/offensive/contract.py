"""Core loop contract types for offensive engines and attack planning.

Types-only module defining pure contracts and protocols for the red/blue loop.
No behavior, no concrete engine imports.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable
from pydantic import BaseModel, Field

from core.time import utcnow


class ExecutionStatus(str, Enum):
    """Overall status of an attack execution run."""

    PENDING = "pending"
    PENDING_APPROVAL = "pending_approval"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    STOPPED = "stopped"


class ActionStatus(str, Enum):
    """Status of an individual attack step execution."""

    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


class AttackStep(BaseModel):
    """An individual emulation or attack step in an offensive plan."""

    step_id: str
    technique_id: str
    name: str
    environment_id: str = "staging-range"
    target_asset: Optional[str] = None
    command_or_action: Optional[str] = None
    prerequisites: List[str] = Field(default_factory=list)
    cleanup_action: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class RedPlan(BaseModel):
    """A planned adversarial sequence emitted by a red planner."""

    plan_id: str
    environment_id: str
    objective: str
    steps: List[AttackStep] = Field(default_factory=list)
    cycle_number: int = 1
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utcnow)


class ActionTraceStep(BaseModel):
    """Recorded action trace entry for a step."""

    step_id: str
    technique_id: str
    status: ActionStatus = ActionStatus.SUCCESS
    timestamp: datetime = Field(default_factory=utcnow)
    executed_action: str
    target_asset: str
    exit_code: Optional[int] = 0
    raw_log: Optional[str] = None


class RedRunResult(BaseModel):
    """Result of executing an adversarial plan against an environment."""

    run_id: str
    plan_id: str
    environment_id: str
    status: ExecutionStatus = ExecutionStatus.COMPLETED
    action_trace: List[ActionTraceStep] = Field(default_factory=list)
    captured_telemetry: List[Dict[str, Any]] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=utcnow)
    completed_at: Optional[datetime] = None
    token_spend: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None
    raw_logs: Optional[str] = None


@runtime_checkable
class OffensiveEngine(Protocol):
    """Contract for offensive attack engines driving red emulation."""

    async def run(
        self,
        plan: RedPlan,
        context: Optional[Dict[str, Any]] = None,
    ) -> RedRunResult:
        """Execute the red plan and return run results."""
        ...

    async def execute(
        self,
        plan: RedPlan,
        context: Optional[Dict[str, Any]] = None,
    ) -> RedRunResult:
        """Alias for run to maintain backward compatibility."""
        ...

    async def validate_environment(self, environment_id: str) -> bool:
        """Verify that the target environment is reachable and authorized."""
        ...
