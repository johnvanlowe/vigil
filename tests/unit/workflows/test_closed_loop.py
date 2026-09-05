"""Unit tests for the ClosedLoopController and multi-cycle re-invocation."""

import pytest

from core.detections.author_policy import AuthoringPolicy
from core.integrations.offensive_engine import (
    AttackPlan,
    StubOffensiveEngine,
    register_offensive_engine,
)
from core.workflows.closed_loop import (
    ClosedLoopConfig,
    ClosedLoopController,
    HaltReason,
)


@pytest.fixture(autouse=True)
def setup_stub_engine():
    """Register stub engine for closed loop tests."""
    register_offensive_engine("stub", StubOffensiveEngine())


@pytest.mark.asyncio
async def test_closed_loop_multi_cycle_reinvocation():
    """Verify loop executes across at least two cycles with re-invocation and posture compounding."""
    config = ClosedLoopConfig(
        environment_id="staging-range",
        objectives=["Emulate adversary lateral movement and credential theft"],
        threat_context="ransomware",
        max_cycles=2,
        max_cost_usd=5.0,
        engine_name="stub",
        policy=AuthoringPolicy(default_action="auto_author", min_confidence=0.90),
    )

    controller = ClosedLoopController(config=config, run_id="test-loop-run-1")
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
    )

    controller = ClosedLoopController(config=config, run_id="test-budget-run")
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
    )

    controller = ClosedLoopController(config=config, run_id="test-max-cycles-run")
    result = await controller.run()

    assert result.total_cycles_executed == 3
    assert result.halt_reason == HaltReason.MAX_CYCLES_REACHED
