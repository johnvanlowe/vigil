"""Test contract types for loop: OffensiveEngine, AttackStep, DetectionVerdict, Candidate, ValidationRecord."""

import sys
from datetime import datetime
import pytest

from core.integrations.offensive.contract import (
    ActionStatus,
    ActionTraceStep,
    AttackStep,
    ExecutionStatus,
    OffensiveEngine,
    RedPlan,
    RedRunResult,
)
from core.detections.candidates import (
    CandidateStatus,
    DetectionCandidate,
    DetectionVerdict,
    ValidationRecord,
    VerdictOutcome,
)


def test_offensive_engine_protocol_conformance():
    """Verify that a minimal stub class satisfies the OffensiveEngine protocol."""
    class DummyEngine:
        async def run(self, plan: RedPlan, context=None) -> RedRunResult:
            return RedRunResult(
                run_id="run-1",
                plan_id=plan.plan_id,
                environment_id=plan.environment_id,
                status=ExecutionStatus.COMPLETED,
            )

        async def execute(self, plan: RedPlan, context=None) -> RedRunResult:
            return await self.run(plan, context)

        async def validate_environment(self, environment_id: str) -> bool:
            return True

    engine = DummyEngine()
    assert isinstance(engine, OffensiveEngine)


def test_contract_types_require_environment_id():
    """Verify that environment_id is present and required on all environment-scoped contracts."""
    step = AttackStep(
        step_id="s1",
        technique_id="T1059.001",
        name="PowerShell execution",
        environment_id="range-prod-01",
    )
    assert step.environment_id == "range-prod-01"

    plan = RedPlan(
        plan_id="p1",
        environment_id="range-prod-01",
        objective="Validate PowerShell detection",
        steps=[step],
    )
    assert plan.environment_id == "range-prod-01"

    verdict = DetectionVerdict(
        step_id="s1",
        technique_id="T1059.001",
        verdict="rule",
        environment_id="range-prod-01",
        matching_rules=["sigma-powershell-enc"],
    )
    assert verdict.environment_id == "range-prod-01"
    assert verdict.verdict == "rule"

    validation = ValidationRecord(
        candidate_id="c1",
        environment_id="range-prod-01",
        is_valid=True,
        passed_lint=True,
        passed_replay=True,
        passed_judge=True,
    )
    assert validation.environment_id == "range-prod-01"

    candidate = DetectionCandidate(
        candidate_id="c1",
        environment_id="range-prod-01",
        technique_id="T1059.001",
        rule_name="Detect Encoded PowerShell",
        rule_content="title: Detect Encoded PS\nlogsource:\n  product: windows",
        rationale="Blocks encoded command execution",
        validation_record=validation,
    )
    assert candidate.environment_id == "range-prod-01"
    assert candidate.status == CandidateStatus.DRAFT


def test_no_concrete_engine_imports():
    """Ensure that importing contracts does not import artemis or external concrete engines."""
    import subprocess
    cmd = [
        sys.executable,
        "-c",
        "import sys; import core.integrations.offensive.contract; import core.detections.candidates; assert 'core.integrations.artemis.adapter' not in sys.modules",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0, f"Importing contract leaked concrete adapter: {res.stderr}"

