"""Tests for closed-loop Playbook execution and halting guarantees."""

import pytest
from core.cli.loop import ClosedLoopRunner, run_loop_cli


@pytest.mark.asyncio
async def test_closed_loop_halts_on_cycle_cap():
    """Verify closed loop halts exactly when reaching max_cycles."""
    runner = ClosedLoopRunner(
        environment_id="temporange",
        max_cycles=2,
        budget_cap_usd=100.0,
    )
    result = await runner.run()

    assert result.cycles_completed == 2
    assert result.halt_reason == "cycle_cap"
    assert len(result.plans) == 2


@pytest.mark.asyncio
async def test_closed_loop_halts_on_budget_cap():
    """Verify closed loop halts when budget envelope is exhausted."""
    # Setting budget cap very low so it cannot execute a cycle
    runner = ClosedLoopRunner(
        environment_id="temporange",
        max_cycles=5,
        budget_cap_usd=0.10,  # Below cycle_estimated_cost of 0.25
    )
    result = await runner.run()

    assert result.cycles_completed == 0
    assert result.halt_reason == "budget_cap"


@pytest.mark.asyncio
async def test_closed_loop_halts_on_operator_stop():
    """Verify closed loop halts immediately if operator issues a stop signal."""
    stop_signal = True

    runner = ClosedLoopRunner(
        environment_id="temporange",
        max_cycles=3,
        budget_cap_usd=100.0,
        operator_stop_check=lambda: stop_signal,
    )
    result = await runner.run()

    assert result.cycles_completed == 0
    assert result.halt_reason == "operator_stop"


@pytest.mark.asyncio
async def test_second_invocation_includes_first_cycle_promotions_in_plan_context():
    """Verify that second cycle reads promoted detections from coverage view and incorporates them into context."""
    runner = ClosedLoopRunner(
        environment_id="temporange",
        max_cycles=2,
        budget_cap_usd=100.0,
    )
    result = await runner.run()

    assert result.cycles_completed == 2
    assert len(result.contexts) == 2
    assert len(result.promoted_detections) > 0

    # Cycle 1 should have had empty prior promotions
    first_ctx = result.contexts[0]
    assert len(first_ctx.prior_promoted_rules) == 0

    # Cycle 2 context must include the promoted detections from cycle 1
    second_ctx = result.contexts[1]
    assert len(second_ctx.prior_promoted_rules) > 0
    promoted_techs_in_ctx = {
        r.get("technique_id") for r in second_ctx.prior_promoted_rules
    }
    for promoted in result.promoted_detections:
        assert promoted["technique_id"] in promoted_techs_in_ctx
