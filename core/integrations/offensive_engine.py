"""Engine-neutral offensive-engine protocol and contracts.

Every offensive tool is a Vendor Slice under ``core/integrations/<vendor>/`` with a
descriptor. Callers in the closed loop program against this ``OffensiveEngine``
protocol, never against concrete engine implementations.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Protocol, Sequence, runtime_checkable

from core.time import utcnow

logger = logging.getLogger(__name__)


class ExecutionStatus(str, Enum):
    """Lifecycle status of an offensive execution."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    STOPPED = "stopped"
    PENDING_APPROVAL = "pending_approval"


class ActionStatus(str, Enum):
    """Execution status of an individual attack action."""

    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"
    SKIPPED = "skipped"


@dataclass
class EnvironmentScope:
    """Scope defining the boundary of authorized target environments.

    Safety invariant: Offensive actions must NEVER run against unauthorized production
    environments. The environment must be explicitly designated as a range, digital
    twin, or staging replica.
    """

    environment_id: str
    environment_type: str = "staging"  # "staging", "range", "digital_twin", "production"
    allowed_asset_ids: List[str] = field(default_factory=list)
    allowed_subnets: List[str] = field(default_factory=list)
    is_production: bool = False
    emergency_override: bool = False

    def is_target_authorized(self, target_asset: Optional[str] = None) -> bool:
        """Verify whether an action targeting an asset is permitted."""
        if self.is_production and not self.emergency_override:
            logger.warning(
                "Execution denied: environment %s is marked production without override.",
                self.environment_id,
            )
            return False
        if not target_asset or not self.allowed_asset_ids:
            return True
        return target_asset in self.allowed_asset_ids


@dataclass
class AttackPlanStep:
    """Atomic step in an attack plan."""

    step_id: str
    technique_id: str  # MITRE ATT&CK technique (e.g. "T1059.001")
    name: str
    description: str
    target_asset: Optional[str] = None
    command_or_action: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    order: int = 0


@dataclass
class AttackPlan:
    """Threat-informed, objective-driven attack plan."""

    plan_id: str
    environment_id: str
    objectives: List[str]
    target_techniques: List[str]
    steps: List[AttackPlanStep]
    seed: Optional[int] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=utcnow)

    @classmethod
    def create(
        cls,
        environment_id: str,
        objectives: List[str],
        target_techniques: List[str],
        steps: Sequence[AttackPlanStep],
        seed: Optional[int] = None,
        parameters: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AttackPlan:
        plan_id = f"plan-{utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}"
        return cls(
            plan_id=plan_id,
            environment_id=environment_id,
            objectives=list(objectives),
            target_techniques=list(target_techniques),
            steps=list(steps),
            seed=seed,
            parameters=parameters or {},
            metadata=metadata or {},
        )


@dataclass
class AttackTraceStep:
    """Executed action observed in the offensive engine's action trace."""

    step_id: str
    technique_id: str
    name: str
    status: ActionStatus
    executed_action: str
    timestamp: datetime = field(default_factory=utcnow)
    target_asset: Optional[str] = None
    raw_log: Optional[str] = None
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackExecutionResult:
    """Complete result emitted by an OffensiveEngine execution."""

    run_id: str
    plan_id: str
    environment_id: str = "staging"
    status: ExecutionStatus = ExecutionStatus.COMPLETED
    action_trace: List[AttackTraceStep] = field(default_factory=list)
    captured_telemetry: List[Dict[str, Any]] = field(default_factory=list)
    started_at: datetime = field(default_factory=utcnow)
    completed_at: datetime = field(default_factory=utcnow)
    token_spend: Dict[str, Any] = field(default_factory=dict)
    raw_logs: Optional[str] = None
    error: Optional[str] = None


@runtime_checkable
class OffensiveEngine(Protocol):
    """Protocol satisfied by all offensive engines (ARTEMIS, Caldera, stubs)."""

    async def execute(
        self,
        plan: AttackPlan,
        context: Optional[Dict[str, Any]] = None,
    ) -> AttackExecutionResult:
        """Execute an attack plan against the designated representative environment."""
        ...

    async def validate_environment(self, environment_id: str) -> bool:
        """Verify whether the environment is reachable and authorized."""
        ...


class StubOffensiveEngine:
    """In-memory stub engine for contract testing and loop verification."""

    def __init__(
        self,
        authorized_environments: Optional[List[str]] = None,
        simulate_failure_step: Optional[str] = None,
    ):
        self.authorized_environments = authorized_environments or [
            "staging",
            "staging-range",
            "range-01",
            "digital-twin",
            "test-env",
        ]
        self.simulate_failure_step = simulate_failure_step
        self.executed_plans: List[AttackPlan] = []

    async def validate_environment(self, environment_id: str) -> bool:
        return any(
            environment_id == e or environment_id.startswith(f"{e}-")
            for e in self.authorized_environments
        )

    async def execute(
        self,
        plan: AttackPlan,
        context: Optional[Dict[str, Any]] = None,
    ) -> AttackExecutionResult:
        self.executed_plans.append(plan)
        now = utcnow()
        run_id = f"red-{now.strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}"

        trace: List[AttackTraceStep] = []
        telemetry: List[Dict[str, Any]] = []

        overall_status = ExecutionStatus.COMPLETED

        for step in plan.steps:
            if self.simulate_failure_step == step.step_id:
                step_status = ActionStatus.FAILED
                overall_status = ExecutionStatus.PARTIAL
            else:
                step_status = ActionStatus.SUCCESS

            trace_step = AttackTraceStep(
                step_id=step.step_id,
                technique_id=step.technique_id,
                name=step.name,
                status=step_status,
                executed_action=step.command_or_action or f"execute {step.technique_id}",
                timestamp=now,
                target_asset=step.target_asset or "host-01.range.local",
                raw_log=f"[STUB] executed {step.name} on {step.target_asset}",
            )
            trace.append(trace_step)

            # Generate synthetic captured telemetry corresponding to the step
            telemetry.append(
                {
                    "event_id": f"evt-{uuid.uuid4().hex[:8]}",
                    "step_id": step.step_id,
                    "technique_id": step.technique_id,
                    "target_asset": step.target_asset or "host-01.range.local",
                    "action": step.command_or_action,
                    "timestamp": now.isoformat(),
                    "source": "sysmon",
                    "data": {
                        "process_name": "powershell.exe",
                        "command_line": step.command_or_action or "powershell -enc ...",
                        "dest_ip": "10.0.0.5",
                        "dest_port": 443,
                    },
                }
            )

        return AttackExecutionResult(
            run_id=run_id,
            plan_id=plan.plan_id,
            environment_id=plan.environment_id,
            status=overall_status,
            action_trace=trace,
            captured_telemetry=telemetry,
            started_at=now,
            completed_at=utcnow(),
            token_spend={
                "prompt_tokens": 500,
                "completion_tokens": 150,
                "cost_usd": 0.005,
            },
            raw_logs="[STUB] execution completed successfully.",
        )


_ENGINES: Dict[str, OffensiveEngine] = {
    "stub": StubOffensiveEngine(),
}


def register_offensive_engine(name: str, engine: OffensiveEngine) -> None:
    """Register an offensive engine under a unique key."""
    _ENGINES[name] = engine


def get_offensive_engine(name: Optional[str] = None) -> OffensiveEngine:
    """Resolve an offensive engine by name, falling back to artemis or stub."""
    key = name or "artemis"
    if key in _ENGINES:
        return _ENGINES[key]

    if key == "artemis":
        from core.integrations.artemis.adapter import ArtemisAdapter

        adapter = ArtemisAdapter()
        _ENGINES["artemis"] = adapter
        return adapter

    raise KeyError(f"Unknown offensive engine: {key!r}. Available: {sorted(_ENGINES)}")
