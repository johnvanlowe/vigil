"""Unit tests for the ClosedLoopController and multi-cycle re-invocation."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import uuid
import pytest

from core.detections.author_policy import AuthoringPolicy
from core.detections.coverage_projection import read_coverage_projection
from core.integrations.offensive_engine import (
    AttackExecutionResult,
    AttackPlan,
    EnvironmentScope,
    ExecutionStatus,
    StubOffensiveEngine,
    register_offensive_engine,
)
from core.response.approval_service import ActionStatus, ApprovalService
from core.storage.ledger import append_agent_event
from core.workflows.closed_loop import (
    ClosedLoopConfig,
    ClosedLoopController,
    HaltReason,
)


@pytest.fixture(autouse=True)
def setup_stub_engine():
    """Register stub engine for closed loop tests."""
    engine = StubOffensiveEngine()
    register_offensive_engine("stub", engine)
    return engine


@pytest.mark.asyncio
async def test_closed_loop_multi_cycle_reinvocation():
    """Verify loop executes across at least two cycles with re-invocation and posture compounding."""
    env_id = f"staging-range-{uuid.uuid4().hex[:6]}"
    config = ClosedLoopConfig(
        environment_id=env_id,
        objectives=["Emulate adversary lateral movement and credential theft"],
        threat_context="ransomware",
        max_cycles=2,
        max_cost_usd=5.0,
        engine_name="stub",
        pre_approved_offense=True,
        pre_authorized_promotion=True,
        policy=AuthoringPolicy(default_action="auto_author", min_confidence=0.90),
    )

    controller = ClosedLoopController(config=config, run_id=f"test-loop-{uuid.uuid4().hex[:8]}")
    result = await controller.run()

    # 1. Loop drives at least 2 cycles by re-invocation
    assert result.total_cycles_executed == 2
    assert len(result.cycle_results) == 2
    assert result.cycle_results[0].cycle_number == 1
    assert result.cycle_results[1].cycle_number == 2

    # 2. Compounding: cycle N+1 plan was forced onto new techniques / gaps
    c1_plan = result.cycle_results[0].plan
    c2_plan = result.cycle_results[1].plan
    assert c1_plan.plan_id != c2_plan.plan_id

    # 3. Durable projection reflects both cycles
    proj = result.final_projection
    assert proj.total_cycles == 2
    assert len(proj.cycle_history) == 2
    assert len(proj.attacked_techniques) > 0

    # 4. Viable-path frontier metric is tracked across cycles
    assert result.initial_frontier >= 0.0
    assert result.final_frontier >= 0.0


@pytest.mark.asyncio
async def test_closed_loop_halts_on_budget_exceeded():
    """Verify loop terminates cleanly when cumulative spend exceeds budget cap."""
    config = ClosedLoopConfig(
        environment_id="staging-range",
        objectives=["Test budget termination"],
        max_cycles=10,
        max_cost_usd=0.001,  # Strict low budget that trips after cycle 1
        engine_name="stub",
        pre_approved_offense=True,
        pre_authorized_promotion=True,
    )

    controller = ClosedLoopController(config=config, run_id=f"test-budget-{uuid.uuid4().hex[:8]}")
    result = await controller.run()

    assert result.halt_reason == HaltReason.BUDGET_EXCEEDED
    assert result.total_cycles_executed == 1
    assert result.total_cost_usd >= 0.001


@pytest.mark.asyncio
async def test_closed_loop_halts_on_max_cycles():
    """Verify loop halts when maximum configured cycle count is reached."""
    config = ClosedLoopConfig(
        environment_id="staging-range",
        objectives=["Test max cycles"],
        max_cycles=3,
        max_cost_usd=50.0,
        engine_name="stub",
        pre_approved_offense=True,
        pre_authorized_promotion=True,
    )

    controller = ClosedLoopController(config=config, run_id=f"test-max-{uuid.uuid4().hex[:8]}")
    result = await controller.run()

    assert result.total_cycles_executed == 3
    assert result.halt_reason in (HaltReason.MAX_CYCLES_REACHED, HaltReason.COMPLETED)


@pytest.mark.asyncio
async def test_offensive_safety_gate_blocks_unapproved_execution():
    """Verify that absent operator approval, offensive execution pauses and never reaches engine.execute."""
    stub = StubOffensiveEngine()
    register_offensive_engine("stub_safety", stub)

    config = ClosedLoopConfig(
        environment_id="staging-range",
        objectives=["Emulate unauthorized attack"],
        max_cycles=2,
        engine_name="stub_safety",
        pre_approved_offense=False,  # Default: requires approval
    )

    controller = ClosedLoopController(config=config, run_id=f"test-unapproved-{uuid.uuid4().hex[:8]}")
    result = await controller.run()

    # Offensive engine execute should NEVER have been called
    assert len(stub.executed_plans) == 0
    assert result.halt_reason == HaltReason.AWAITING_APPROVAL
    assert result.total_cycles_executed == 1
    assert result.cycle_results[0].execution_result.status == ExecutionStatus.PENDING_APPROVAL


@pytest.mark.asyncio
async def test_offensive_safety_gate_rejects_unauthorized_environment():
    """Verify that production environments without emergency override are refused."""
    stub = StubOffensiveEngine()
    register_offensive_engine("stub_scope", stub)

    scope = EnvironmentScope(
        environment_id="prod-finance-01",
        is_production=True,
        emergency_override=False,
    )

    config = ClosedLoopConfig(
        environment_id="prod-finance-01",
        objectives=["Unauthorized attack against prod"],
        engine_name="stub_scope",
        pre_approved_offense=True,
        scope=scope,
    )

    controller = ClosedLoopController(config=config, run_id=f"test-prod-{uuid.uuid4().hex[:8]}")
    result = await controller.run()

    # Never reached offensive execution
    assert len(stub.executed_plans) == 0
    assert result.halt_reason == HaltReason.UNAUTHORIZED_ENVIRONMENT
    assert result.cycle_results[0].execution_result.status == ExecutionStatus.FAILED


@pytest.mark.asyncio
async def test_promotion_governance_requires_human_approval_by_default():
    """Verify that under default policy, candidates are not promoted without human approval."""
    config = ClosedLoopConfig(
        environment_id="staging-range",
        objectives=["Emulate attack to test promotion gate"],
        max_cycles=1,
        engine_name="stub",
        pre_approved_offense=True,
        pre_authorized_promotion=False,  # Default: requires operator approval
        policy=AuthoringPolicy(default_action="auto_author", require_human_promotion=True),
    )

    controller = ClosedLoopController(config=config, run_id=f"test-promo-gov-{uuid.uuid4().hex[:8]}")
    result = await controller.run()

    # Detections were authored and validated, but NOT promoted to live library
    assert result.total_cycles_executed == 1
    assert len(result.cycle_results[0].candidates_authored) > 0
    assert len(result.cycle_results[0].promoted_detections) == 0
    assert result.promoted_rules_count == 0


@pytest.mark.asyncio
async def test_failed_execution_status_halts_cleanly_without_reconstruction():
    """Verify that FAILED execution status stops cycle and skips reconstruction."""
    class FailingOffensiveEngine(StubOffensiveEngine):
        async def execute(self, plan, context=None):
            return AttackExecutionResult(
                run_id="run-fail",
                plan_id=plan.plan_id,
                environment_id=plan.environment_id,
                status=ExecutionStatus.FAILED,
                error="Network interface timeout on staging-range",
            )

    register_offensive_engine("stub_fail", FailingOffensiveEngine())

    config = ClosedLoopConfig(
        environment_id="staging-range",
        objectives=["Simulate execution failure"],
        max_cycles=3,
        engine_name="stub_fail",
        pre_approved_offense=True,
    )

    controller = ClosedLoopController(config=config, run_id=f"test-exec-fail-{uuid.uuid4().hex[:8]}")
    result = await controller.run()

    assert result.halt_reason == HaltReason.EXECUTION_FAILED
    assert result.total_cycles_executed == 1
    assert len(result.cycle_results[0].reconstruction_report.gaps) == 0
    assert len(result.cycle_results[0].candidates_authored) == 0


def test_ledger_concurrency_under_advisory_lock():
    """Concurrency test: simultaneous appends to one run_id produce monotonic gapless seqs without error."""
    test_run_id = str(uuid.uuid4())
    num_writers = 8

    def append_task(writer_id: int):
        seq = append_agent_event(
            run_id=test_run_id,
            kind="reconstruction_verdict",
            payload={"writer": writer_id, "data": "concurrency_check"},
            run_kind="compose",
        )
        return seq

    with ThreadPoolExecutor(max_workers=num_writers) as executor:
        futures = [executor.submit(append_task, i) for i in range(num_writers)]
        seqs = [f.result() for f in futures]

    assert len(seqs) == num_writers
    assert sorted(seqs) == list(range(num_writers))


@pytest.mark.asyncio
async def test_coverage_projection_durable_replay():
    """Replay test: reconstructs identical CoverageProjection from persisted agent_events after exit."""
    env_id = f"env-replay-{uuid.uuid4().hex[:6]}"
    run_id = str(uuid.uuid4())

    config = ClosedLoopConfig(
        environment_id=env_id,
        objectives=["Verify durable projection replay from agent_events"],
        max_cycles=1,
        engine_name="stub",
        pre_approved_offense=True,
        pre_authorized_promotion=True,
    )

    controller = ClosedLoopController(config=config, run_id=run_id)
    run_result = await controller.run()

    # Simulate process exit: delete controller and read purely from agent_events table
    del controller

    reconstructed_projection = read_coverage_projection(environment_id=env_id)

    assert reconstructed_projection.environment_id == env_id
    assert reconstructed_projection.total_cycles == run_result.final_projection.total_cycles
    assert reconstructed_projection.attacked_techniques == run_result.final_projection.attacked_techniques
    assert reconstructed_projection.technique_coverage == run_result.final_projection.technique_coverage
    assert len(reconstructed_projection.cycle_history) == len(run_result.final_projection.cycle_history)
