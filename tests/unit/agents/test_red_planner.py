"""Unit tests for the red planning role and context assembly."""

import pytest

from core.agents.red_planner import RedPlanner, RedPlannerContext
from core.integrations.offensive_engine import AttackPlan


@pytest.mark.asyncio
async def test_red_planner_context_assembly():
    """Verify red planner gathers detection gaps, topology, and anomaly context."""
    planner = RedPlanner()
    ctx = await planner.assemble_context(
        environment_id="staging-range",
        objectives=["Emulate ransomware kill chain"],
        threat_context="ransomware",
    )

    assert ctx.environment_id == "staging-range"
    assert len(ctx.objectives) == 1
    assert len(ctx.identified_gaps) > 0
    assert len(ctx.topology_assets) > 0
    assert len(ctx.loglm_anomalies) > 0


@pytest.mark.asyncio
async def test_red_planner_plan_generation():
    """Verify AttackPlan is emitted against OffensiveEngine contract and prioritizes gaps."""
    planner = RedPlanner()
    ctx = await planner.assemble_context(
        environment_id="staging-range",
        objectives=["Compromise domain controller"],
    )

    plan = planner.generate_plan(ctx, seed=42)

    assert isinstance(plan, AttackPlan)
    assert plan.environment_id == "staging-range"
    assert plan.seed == 42
    assert len(plan.steps) > 0

    # Ensure MITRE techniques in plan correspond to identified gaps
    techniques_planned = {s.technique_id for s in plan.steps}
    gap_techniques = {g.get("technique") for g in ctx.identified_gaps}
    assert bool(techniques_planned & gap_techniques)

    # Ensure metadata records planner facts
    assert plan.metadata["planner_agent_id"] == "red_planner"


@pytest.mark.asyncio
async def test_red_planner_forces_harder_path_on_promoted_rules():
    """Verify techniques closed in prior cycles are bypassed to force red onto harder seams."""
    planner = RedPlanner()
    ctx = RedPlannerContext(
        environment_id="staging-range",
        objectives=["Test evasions"],
        identified_gaps=[
            {"technique": "T1059.001", "priority": "high"},
            {"technique": "T1003", "priority": "high"},
        ],
        topology_assets=[{"asset_id": "srv-01", "role": "server"}],
        prior_promoted_rules=[
            {"rule_id": "rule-sigma-powershell", "technique_id": "T1059.001"}
        ],
    )

    plan = planner.generate_plan(ctx)
    techniques = [s.technique_id for s in plan.steps]

    # T1059.001 was already closed, so plan must skip it and target T1003!
    assert "T1059.001" not in techniques
    assert "T1003" in techniques
