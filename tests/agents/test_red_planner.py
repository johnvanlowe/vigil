"""Tests for Red Planner role: context assembly, contract RedPlan, citations, and approval gate."""

import pytest
from core.agents.red_planner import RedPlanner, RedPlannerContext
from core.integrations.offensive.contract import RedPlan


@pytest.mark.asyncio
async def test_red_planner_context_assembly_gaps_present():
    """Verify context assembly when detection gaps are present."""
    planner = RedPlanner()
    ctx = await planner.assemble_context(
        environment_id="staging-range",
        objectives=["Assess ransomware resilience"],
        gaps=[
            {"technique": "T1486", "priority": "high"},
            {"technique": "T1490", "priority": "high"},
        ],
    )
    assert ctx.environment_id == "staging-range"
    assert len(ctx.identified_gaps) == 2
    assert ctx.identified_gaps[0]["technique"] == "T1486"


@pytest.mark.asyncio
async def test_red_planner_context_assembly_gaps_absent():
    """Verify context assembly when detection gaps are absent (falls back to evasion)."""
    planner = RedPlanner()
    ctx = await planner.assemble_context(
        environment_id="staging-range",
        objectives=["Assess perimeter"],
        gaps=[],  # Empty gaps
    )
    assert len(ctx.identified_gaps) == 0
    plan = planner.generate_red_plan(ctx)
    assert isinstance(plan, RedPlan)
    assert len(plan.steps) >= 1
    # Fallback evasive technique
    assert plan.steps[0].technique_id == "T1071.001"


@pytest.mark.asyncio
async def test_red_planner_context_assembly_loglm_present_vs_absent():
    """Verify context assembly with LogLM anomalies present vs absent."""
    planner = RedPlanner()

    # LogLM present
    ctx_with_loglm = await planner.assemble_context(
        environment_id="staging-range",
        objectives=["Test anomalies"],
        include_loglm=True,
    )
    assert len(ctx_with_loglm.loglm_anomalies) > 0

    # LogLM absent
    ctx_without_loglm = await planner.assemble_context(
        environment_id="staging-range",
        objectives=["Test anomalies"],
        include_loglm=False,
    )
    assert len(ctx_without_loglm.loglm_anomalies) == 0


@pytest.mark.asyncio
async def test_red_planner_emits_contract_red_plan_with_citations():
    """Verify RedPlan conforms to contract and cites gap analysis and topology."""
    planner = RedPlanner()
    ctx = await planner.assemble_context(
        environment_id="staging-range",
        objectives=["Compromise domain controller"],
        gaps=[
            {"technique": "T1003", "priority": "high"},
            {"technique": "T1059.001", "priority": "medium"},
        ],
        assets=[
            {"asset_id": "srv-dc-01", "role": "domain_controller", "segment": "internal"},
            {"asset_id": "srv-web-01", "role": "web_server", "segment": "dmz"},
        ],
    )

    plan = planner.generate_red_plan(ctx, cycle_number=1)
    assert isinstance(plan, RedPlan)
    assert plan.environment_id == "staging-range"
    assert len(plan.steps) == 2

    # Check citations
    assert "gaps_cited" in plan.metadata
    assert "T1003" in plan.metadata["gaps_cited"]
    assert "srv-dc-01" in plan.metadata["topology_assets_cited"]

    # Credential dumping should target domain controller
    step_t1003 = next(s for s in plan.steps if s.technique_id == "T1003")
    assert step_t1003.target_asset == "srv-dc-01"


def test_offensive_tools_are_approval_gated():
    """Verify offensive plans specify pending_approval and pause_by_default policy."""
    planner = RedPlanner()
    ctx = RedPlannerContext(
        environment_id="staging-range",
        objectives=["Assess resilience"],
        identified_gaps=[{"technique": "T1059.001"}],
        topology_assets=[{"asset_id": "host-1"}],
    )
    plan = planner.generate_red_plan(ctx)
    assert plan.metadata["approval_status"] == "pending_approval"
    assert plan.metadata["execution_policy"] == "pause_by_default"
