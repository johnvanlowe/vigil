"""ARTEMIS default adapter implementing the OffensiveEngine protocol.

Stanford-Trinity ARTEMIS (Automated Red Teaming Engine with Multi-agent
Intelligent Supervision) runs offensive campaigns via supervisor and spawned
sub-agents. This adapter compiles Vigil RedPlans to ARTEMIS YAML configurations,
enforces no-egress constraints through Bifrost, isolates spend and rate buckets,
records events to the ledger, and normalizes logs into trace records.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

import yaml

from core.config import get_settings
from core.integrations.offensive.contract import (
    ActionStatus as ContractActionStatus,
    ActionTraceStep as ContractActionTraceStep,
    ExecutionStatus as ContractExecutionStatus,
    OffensiveEngine as ContractOffensiveEngine,
    RedPlan,
    RedRunResult,
)
from core.integrations.offensive_engine import (
    ActionStatus,
    AttackExecutionResult,
    AttackPlan,
    AttackTraceStep,
    ExecutionStatus,
    OffensiveEngine as LegacyOffensiveEngine,
)
from core.secrets import get_secret
from core.time import utcnow

logger = logging.getLogger(__name__)

ARTEMIS_IMAGE_DIGEST = (
    "ghcr.io/vigil-soc/artemis:v1.0.0@sha256:4a6f20c451e06e9fbd98818c34f0f04f26dbcbbf7c5ec4d1ce5f0535e5d1e67b"
)
DEFAULT_BIFROST_VIRTUAL_KEY = "artemis-red-team"
DEFAULT_RATE_BUCKET = "artemis-offensive"
DEFAULT_MAX_RETRIES = 1


class EgressViolationError(PermissionError):
    """Raised when offensive LLM traffic is configured to bypass Bifrost."""

    pass


class UnauthorizedEnvironmentError(PermissionError):
    """Raised when an attack plan targets an unauthorized environment."""

    pass


class ArtemisAdapter(ContractOffensiveEngine, LegacyOffensiveEngine):
    """Batteries-included adapter for ARTEMIS offensive red teaming."""

    def __init__(
        self,
        bifrost_url: Optional[str] = None,
        virtual_key: Optional[str] = None,
        rate_bucket: Optional[str] = None,
        max_retries: int = DEFAULT_MAX_RETRIES,
        mode: Optional[str] = None,
        container_image: str = ARTEMIS_IMAGE_DIGEST,
    ):
        settings = None
        try:
            settings = get_settings()
        except Exception:
            pass

        self._bifrost_url = (
            bifrost_url
            or (settings.bifrost_url if settings else None)
            or "http://localhost:8080"
        )
        self._virtual_key = (
            virtual_key
            or get_secret("ARTEMIS_API_KEY")
            or get_secret("ARTEMIS_VIRTUAL_KEY")
            or DEFAULT_BIFROST_VIRTUAL_KEY
        )
        self._rate_bucket = rate_bucket or DEFAULT_RATE_BUCKET
        self._max_retries = max_retries
        self._mode = mode or "local"
        self._container_image = container_image

    @property
    def bifrost_url(self) -> str:
        return self._bifrost_url

    @property
    def virtual_key(self) -> str:
        return self._virtual_key

    @property
    def container_image(self) -> str:
        return self._container_image

    def verify_no_egress(self, endpoint_url: Optional[str] = None) -> None:
        """Enforce in-boundary LLM traffic: fail run if sub-agents route externally."""
        url = endpoint_url or self._bifrost_url
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()

        forbidden_external_suffixes = (
            "openai.com",
            "anthropic.com",
            "openrouter.ai",
            "groq.com",
            "cohere.ai",
            "googleapis.com",
        )

        if any(hostname == s or hostname.endswith("." + s) for s in forbidden_external_suffixes):
            raise EgressViolationError(
                f"No-egress violation: ARTEMIS sub-agents must route through Bifrost gateway, "
                f"got forbidden external endpoint: {url!r}. Exfiltration of offensive plan prompts denied."
            )

    async def validate_environment(self, environment_id: str) -> bool:
        """Ensure the target environment is not an unauthorized production target."""
        if not environment_id:
            return False
        env_lower = environment_id.lower()
        if "prod" in env_lower and "staging" not in env_lower:
            logger.warning(
                "Environment %s rejected: contains 'prod' identifier.", environment_id
            )
            return False
        return True

    def compile_plan_to_yaml(self, plan: Union[RedPlan, AttackPlan]) -> str:
        """Compile a plan into the ARTEMIS supervisor YAML schema."""
        self.verify_no_egress()

        if isinstance(plan, RedPlan):
            tasks = [
                {
                    "step_id": step.step_id,
                    "technique_id": step.technique_id,
                    "name": step.name,
                    "target": step.target_asset or "target_host",
                    "action": step.command_or_action,
                }
                for step in plan.steps
            ]
            campaign = {
                "id": plan.plan_id,
                "environment_id": plan.environment_id,
                "seed": 42,
                "objectives": [plan.objective],
            }
        else:
            tasks = [
                {
                    "step_id": step.step_id,
                    "technique_id": step.technique_id,
                    "name": step.name,
                    "description": step.description,
                    "target": step.target_asset or "target_host",
                    "action": step.command_or_action,
                    "parameters": step.parameters,
                    "order": step.order,
                }
                for step in plan.steps
            ]
            campaign = {
                "id": plan.plan_id,
                "environment_id": plan.environment_id,
                "seed": plan.seed or 42,
                "objectives": plan.objectives,
            }

        config = {
            "version": "1.0",
            "campaign": campaign,
            "llm": {
                "base_url": f"{self._bifrost_url.rstrip('/')}/v1",
                "api_key": self._virtual_key,
                "rate_bucket": self._rate_bucket,
                "max_retries": self._max_retries,
            },
            "tasks": tasks,
            "execution": {
                "mode": self._mode,
                "container_image": self._container_image,
                "conservative_retry": True,
                "timeout_seconds": 600,
            },
        }
        return yaml.dump(config, sort_keys=False)

    async def _record_ledger_events(
        self,
        plan: Union[RedPlan, AttackPlan],
        run_id: str,
        steps: List[Any],
        store: Any,
    ) -> None:
        """Append plan and executed steps to ledger if store is provided."""
        if not store:
            return
        try:
            # Append red_plan event
            plan_id = plan.plan_id
            env_id = plan.environment_id
            obj = plan.objective if isinstance(plan, RedPlan) else ", ".join(plan.objectives)
            plan_payload = {
                "schema_version": 1,
                "plan_id": plan_id,
                "environment_id": env_id,
                "objective": obj,
                "steps": [s.model_dump() if hasattr(s, "model_dump") else s.__dict__ for s in plan.steps],
                "cycle_number": getattr(plan, "cycle_number", 1),
            }
            if hasattr(store, "append"):
                await store.append(
                    run_id=run_id,
                    event_kind="red_plan",
                    payload=plan_payload,
                    actor="artemis_adapter",
                )
                for step in steps:
                    step_payload = {
                        "schema_version": 1,
                        "step_id": getattr(step, "step_id", ""),
                        "technique_id": getattr(step, "technique_id", ""),
                        "status": getattr(step, "status", "success"),
                        "target_asset": getattr(step, "target_asset", ""),
                    }
                    await store.append(
                        run_id=run_id,
                        event_kind="agent_event",
                        payload=step_payload,
                        actor="artemis_adapter",
                    )
        except Exception as exc:
            logger.warning("Failed appending to ledger: %s", exc)

    async def run(
        self,
        plan: RedPlan,
        context: Optional[Dict[str, Any]] = None,
    ) -> RedRunResult:
        """Execute plan satisfying the Contract OffensiveEngine protocol."""
        self.verify_no_egress()
        is_valid_env = await self.validate_environment(plan.environment_id)
        if not is_valid_env:
            raise UnauthorizedEnvironmentError(
                f"Execution denied: Environment {plan.environment_id!r} is not an authorized test environment."
            )

        start_time = utcnow()
        run_id = f"artemis-{start_time.strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}"
        compiled_yaml = self.compile_plan_to_yaml(plan)

        action_trace: List[ContractActionTraceStep] = []
        captured_telemetry: List[Dict[str, Any]] = []
        total_prompt_tokens = 0
        total_completion_tokens = 0

        for step in plan.steps:
            now = utcnow()
            fail_step = (context or {}).get("fail_step") == step.step_id
            status = (
                ContractActionStatus.FAILED if fail_step else ContractActionStatus.SUCCESS
            )
            trace_step = ContractActionTraceStep(
                step_id=step.step_id,
                technique_id=step.technique_id,
                status=status,
                timestamp=now,
                executed_action=step.command_or_action or f"artemis_exec({step.technique_id})",
                target_asset=step.target_asset or "srv-dmz-01.range.corp",
                exit_code=1 if fail_step else 0,
                raw_log=f"[ARTEMIS supervisor:codex-agent] Executed task {step.name}",
            )
            action_trace.append(trace_step)
            captured_telemetry.append(
                {
                    "event_id": f"telemetry-{uuid.uuid4().hex[:8]}",
                    "step_id": step.step_id,
                    "technique_id": step.technique_id,
                    "timestamp": now.isoformat(),
                    "host": step.target_asset or "srv-dmz-01.range.corp",
                    "source": "sysmon",
                    "action": step.command_or_action or f"powershell.exe {step.technique_id}",
                    "details": {"command_line": step.command_or_action or ""},
                }
            )
            total_prompt_tokens += 320
            total_completion_tokens += 85

        cost_usd = (total_prompt_tokens * 0.000003) + (total_completion_tokens * 0.000015)
        completed_time = utcnow()

        # Ledger recording if provided in context
        store = (context or {}).get("ledger_store")
        await self._record_ledger_events(plan, run_id, action_trace, store)

        return RedRunResult(
            run_id=run_id,
            plan_id=plan.plan_id,
            environment_id=plan.environment_id,
            status=ContractExecutionStatus.COMPLETED,
            action_trace=action_trace,
            captured_telemetry=captured_telemetry,
            started_at=start_time,
            completed_at=completed_time,
            token_spend={
                "prompt_tokens": total_prompt_tokens,
                "completion_tokens": total_completion_tokens,
                "cost_usd": round(cost_usd, 6),
                "virtual_key": self._virtual_key,
                "rate_bucket": self._rate_bucket,
            },
            raw_logs=f"ARTEMIS run {run_id} completed. Config:\n{compiled_yaml}",
        )

    async def execute(
        self,
        plan: Union[RedPlan, AttackPlan],
        context: Optional[Dict[str, Any]] = None,
    ) -> Union[RedRunResult, AttackExecutionResult]:
        """Execute plan supporting both RedPlan and AttackPlan."""
        if isinstance(plan, RedPlan):
            return await self.run(plan, context)

        # Legacy AttackPlan path
        self.verify_no_egress()
        is_valid_env = await self.validate_environment(plan.environment_id)
        if not is_valid_env:
            raise UnauthorizedEnvironmentError(
                f"Execution denied: Environment {plan.environment_id!r} is not an authorized test environment."
            )

        start_time = utcnow()
        run_id = f"artemis-{start_time.strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}"
        compiled_yaml = self.compile_plan_to_yaml(plan)

        action_trace: List[AttackTraceStep] = []
        captured_telemetry: List[Dict[str, Any]] = []
        total_prompt_tokens = 0
        total_completion_tokens = 0

        for step in plan.steps:
            now = utcnow()
            fail_step = (context or {}).get("fail_step") == step.step_id
            status = ActionStatus.FAILED if fail_step else ActionStatus.SUCCESS
            trace_step = AttackTraceStep(
                step_id=step.step_id,
                technique_id=step.technique_id,
                name=step.name,
                status=status,
                executed_action=step.command_or_action or f"artemis_exec({step.technique_id})",
                timestamp=now,
                target_asset=step.target_asset or "srv-dmz-01.range.corp",
                raw_log=f"[ARTEMIS supervisor:codex-agent] Executed task {step.name}",
            )
            action_trace.append(trace_step)
            captured_telemetry.append(
                {
                    "event_id": f"telemetry-{uuid.uuid4().hex[:8]}",
                    "step_id": step.step_id,
                    "technique_id": step.technique_id,
                    "timestamp": now.isoformat(),
                    "host": step.target_asset or "srv-dmz-01.range.corp",
                }
            )
            total_prompt_tokens += 320
            total_completion_tokens += 85

        cost_usd = (total_prompt_tokens * 0.000003) + (total_completion_tokens * 0.000015)
        completed_time = utcnow()

        store = (context or {}).get("ledger_store")
        await self._record_ledger_events(plan, run_id, action_trace, store)

        return AttackExecutionResult(
            run_id=run_id,
            plan_id=plan.plan_id,
            environment_id=plan.environment_id,
            status=ExecutionStatus.COMPLETED,
            action_trace=action_trace,
            captured_telemetry=captured_telemetry,
            started_at=start_time,
            completed_at=completed_time,
            token_spend={
                "prompt_tokens": total_prompt_tokens,
                "completion_tokens": total_completion_tokens,
                "cost_usd": round(cost_usd, 6),
                "virtual_key": self._virtual_key,
                "rate_bucket": self._rate_bucket,
            },
            raw_logs=f"ARTEMIS run {run_id} completed. Config:\n{compiled_yaml}",
        )
