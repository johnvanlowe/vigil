"""Tests for ARTEMIS adapter, OffensiveEngine contract, and egress constraints."""

import pytest
from core.config import get_settings
from core.integrations.artemis.adapter import (
    ARTEMIS_IMAGE_DIGEST,
    ArtemisAdapter,
    EgressViolationError,
    UnauthorizedEnvironmentError,
)
from core.integrations.offensive.contract import (
    AttackStep,
    OffensiveEngine,
    RedPlan,
)
from core.integrations.offensive.stub import StubOffensiveEngine


def test_artemis_enabled_defaults_false():
    """Verify integrations.artemis.enabled defaults to False."""
    settings = get_settings()
    assert getattr(settings, "integrations_artemis_enabled", False) is False


def test_artemis_container_pinned_by_digest():
    """Verify container is pinned by sha256 digest."""
    adapter = ArtemisAdapter()
    assert "@sha256:" in adapter.container_image
    assert adapter.container_image == ARTEMIS_IMAGE_DIGEST


def test_artemis_implements_offensive_engine_protocol():
    """Verify ArtemisAdapter satisfies OffensiveEngine protocol."""
    adapter = ArtemisAdapter()
    assert isinstance(adapter, OffensiveEngine)


def test_offensive_engine_contract_satisfied_by_stub():
    """Verify loop is not ARTEMIS-bound; StubOffensiveEngine satisfies contract."""
    stub = StubOffensiveEngine()
    assert isinstance(stub, OffensiveEngine)


def test_egress_violation_enforcement():
    """Verify egress violation is raised if sub-agent endpoint points to forbidden commercial LLMs."""
    adapter = ArtemisAdapter(bifrost_url="https://api.openai.com/v1")
    with pytest.raises(EgressViolationError):
        adapter.verify_no_egress()

    adapter_anthropic = ArtemisAdapter(bifrost_url="https://api.anthropic.com")
    with pytest.raises(EgressViolationError):
        adapter_anthropic.verify_no_egress()

    # Valid Bifrost endpoint does not raise
    valid_adapter = ArtemisAdapter(bifrost_url="http://bifrost:8080")
    valid_adapter.verify_no_egress()


@pytest.mark.asyncio
async def test_artemis_run_and_ledger_events():
    """Verify ARTEMIS runs a RedPlan and appends schema v1 ledger events."""
    class MockLedgerStore:
        def __init__(self):
            self.events = []

        async def append(self, run_id: str, event_kind: str, payload: dict, actor: str = "artemis_adapter"):
            self.events.append({"run_id": run_id, "kind": event_kind, "payload": payload, "actor": actor})

    store = MockLedgerStore()
    adapter = ArtemisAdapter(
        bifrost_url="http://localhost:8080",
        virtual_key="artemis-key-123",
        rate_bucket="artemis-offensive",
    )

    plan = RedPlan(
        plan_id="plan-test-001",
        environment_id="staging-range",
        objective="Assess lateral movement",
        steps=[
            AttackStep(
                step_id="step-1",
                technique_id="T1047",
                name="WMI Test",
                environment_id="staging-range",
                target_asset="srv-01",
                command_or_action="wmic process call create cmd",
            )
        ],
    )

    result = await adapter.run(plan, context={"ledger_store": store})
    assert result.status.value == "completed"
    assert len(result.action_trace) == 1
    assert result.action_trace[0].technique_id == "T1047"
    assert result.token_spend["virtual_key"] == "artemis-key-123"
    assert result.token_spend["rate_bucket"] == "artemis-offensive"

    # Verify ledger events
    assert len(store.events) == 2  # red_plan + 1 agent_event
    red_plan_event = store.events[0]
    assert red_plan_event["kind"] == "red_plan"
    assert red_plan_event["payload"]["schema_version"] == 1
    assert red_plan_event["payload"]["plan_id"] == "plan-test-001"

    step_event = store.events[1]
    assert step_event["kind"] == "agent_event"
    assert step_event["payload"]["schema_version"] == 1
    assert step_event["payload"]["step_id"] == "step-1"


@pytest.mark.asyncio
async def test_unauthorized_prod_environment_rejected():
    """Verify unauthorized production environments are rejected."""
    adapter = ArtemisAdapter()
    plan = RedPlan(
        plan_id="plan-prod-001",
        environment_id="prod-finance-db",
        objective="Dangerous prod run",
        steps=[],
    )
    with pytest.raises(UnauthorizedEnvironmentError):
        await adapter.run(plan)
