"""Deterministic StubOffensiveEngine for testing and dry runs.

Loads the recorded red run fixture (or synthetic attack traces) and returns
a standardized RedRunResult conforming to the OffensiveEngine protocol.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.integrations.offensive.contract import (
    ActionStatus,
    ActionTraceStep,
    ExecutionStatus,
    OffensiveEngine,
    RedPlan,
    RedRunResult,
)
from core.time import utcnow


class StubOffensiveEngine:
    """Deterministic stub offensive engine satisfying OffensiveEngine Protocol."""

    def __init__(
        self,
        fixture_dir: Optional[Path] = None,
        authorized_environments: Optional[List[str]] = None,
    ):
        self.fixture_dir = fixture_dir or (
            Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "redrun_v1"
        )
        self.authorized_environments = authorized_environments or [
            "staging-range",
            "test-env",
            "sandbox-01",
        ]

    async def validate_environment(self, environment_id: str) -> bool:
        """Validate if the environment is an authorized test range."""
        if not environment_id:
            return False
        env_lower = environment_id.lower()
        if "prod" in env_lower and "staging" not in env_lower:
            return False
        return True

    def load_fixture_trace(self) -> List[ActionTraceStep]:
        """Load ActionTraceStep records from fixture."""
        trace_path = self.fixture_dir / "trace.json"
        if not trace_path.exists():
            return []
        with open(trace_path, "r", encoding="utf-8") as f:
            raw_steps = json.load(f)
        trace_steps: List[ActionTraceStep] = []
        for step in raw_steps:
            trace_steps.append(
                ActionTraceStep(
                    step_id=step["step_id"],
                    technique_id=step["technique_id"],
                    status=ActionStatus(step.get("status", "success")),
                    executed_action=step.get("executed_action", ""),
                    target_asset=step.get("target_asset", "target_host"),
                    exit_code=step.get("exit_code", 0),
                    raw_log=step.get("raw_log"),
                )
            )
        return trace_steps

    def load_fixture_telemetry(self) -> List[Dict[str, Any]]:
        """Load telemetry rows from CSV fixture."""
        telemetry_path = self.fixture_dir / "telemetry.csv"
        if not telemetry_path.exists():
            return []
        rows: List[Dict[str, Any]] = []
        with open(telemetry_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(dict(row))
        return rows

    def load_expected_verdicts(self) -> List[Dict[str, Any]]:
        """Load expected verdicts from fixture."""
        verdict_path = self.fixture_dir / "expected_verdicts.json"
        if not verdict_path.exists():
            return []
        with open(verdict_path, "r", encoding="utf-8") as f:
            return json.load(f)

    async def run(
        self,
        plan: RedPlan,
        context: Optional[Dict[str, Any]] = None,
    ) -> RedRunResult:
        """Execute the red plan deterministically."""
        is_valid = await self.validate_environment(plan.environment_id)
        if not is_valid:
            return RedRunResult(
                run_id=f"stub-{plan.plan_id}-error",
                plan_id=plan.plan_id,
                environment_id=plan.environment_id,
                status=ExecutionStatus.FAILED,
                error=f"Unauthorized environment: {plan.environment_id}",
            )

        # If plan steps match the fixture, use fixture steps, else map plan steps
        fixture_trace = self.load_fixture_trace()
        trace_by_step = {s.step_id: s for s in fixture_trace}

        executed_trace: List[ActionTraceStep] = []
        for step in plan.steps:
            if step.step_id in trace_by_step:
                executed_trace.append(trace_by_step[step.step_id])
            else:
                executed_trace.append(
                    ActionTraceStep(
                        step_id=step.step_id,
                        technique_id=step.technique_id,
                        status=ActionStatus.SUCCESS,
                        executed_action=step.command_or_action or f"exec {step.technique_id}",
                        target_asset=step.target_asset or "target_host",
                        exit_code=0,
                        raw_log=f"Stub execution of {step.name}",
                    )
                )

        telemetry = self.load_fixture_telemetry()
        now = utcnow()

        return RedRunResult(
            run_id=f"stub-run-{plan.plan_id}-{plan.cycle_number}",
            plan_id=plan.plan_id,
            environment_id=plan.environment_id,
            status=ExecutionStatus.COMPLETED,
            action_trace=executed_trace,
            captured_telemetry=telemetry,
            started_at=now,
            completed_at=now,
            token_spend={
                "prompt_tokens": 1500,
                "completion_tokens": 420,
                "cost_usd": 0.015,
            },
            raw_logs=f"Stub offensive run completed for plan {plan.plan_id}",
        )

    async def execute(
        self,
        plan: RedPlan,
        context: Optional[Dict[str, Any]] = None,
    ) -> RedRunResult:
        """Alias for run."""
        return await self.run(plan, context)
