"""Unit tests for the ARTEMIS offensive red teaming adapter and OffensiveEngine contract."""

import pytest
import yaml

from core.integrations.artemis.adapter import (
    ArtemisAdapter,
    EgressViolationError,
    UnauthorizedEnvironmentError,
)
from core.integrations.offensive_engine import (
    ActionStatus,
    AttackPlan,
    AttackPlanStep,
    EnvironmentScope,
    ExecutionStatus,
    OffensiveEngine,
    StubOffensiveEngine,
    get_offensive_engine,
    register_offensive_engine,
)


@pytest.mark.unit
def test_offensive_engine_protocol_conformance():
    """Verify both ArtemisAdapter and StubOffensiveEngine satisfy the OffensiveEngine protocol."""
    assert issubclass(ArtemisAdapter, OffensiveEngine)
    assert issubclass(StubOffensiveEngine, OffensiveEngine)

    stub = StubOffensiveEngine()
    assert isinstance(stub, OffensiveEngine)

    adapter = ArtemisAdapter()
    assert isinstance(adapter, OffensiveEngine)


@pytest.mark.unit
def test_engine_registry_resolution():
    """Verify the factory resolves the configured engine and supports swapping."""
    stub = StubOffensiveEngine()
    register_offensive_engine("custom_caldera", stub)

    resolved = get_offensive_engine("custom_caldera")
    assert resolved is stub

    default_engine = get_offensive_engine("stub")
    assert isinstance(default_engine, StubOffensiveEngine)


@pytest.mark.unit
def test_environment_scope_safety():
    """Verify EnvironmentScope denies un-overridden production execution."""
    staging = EnvironmentScope(environment_id="staging-01", is_production=False)
    assert staging.is_target_authorized("web-01") is True

    prod = EnvironmentScope(environment_id="prod-east", is_production=True, emergency_override=False)
    assert prod.is_target_authorized("web-01") is False

    prod_override = EnvironmentScope(
        environment_id="prod-east",
        is_production=True,
        emergency_override=True,
    )
    assert prod_override.is_target_authorized("web-01") is True


@pytest.mark.unit
def test_artemis_no_egress_enforcement():
    """Verify ArtemisAdapter fails loudly if pointed at public commercial API endpoints."""
    # Forbidden external hosts must raise EgressViolationError
    bad_urls = [
        "https://api.openai.com/v1",
        "https://api.anthropic.com/v1",
        "https://openrouter.ai/api/v1",
    ]
    for url in bad_urls:
        adapter = ArtemisAdapter(bifrost_url=url)
        with pytest.raises(EgressViolationError, match="No-egress violation"):
            adapter.verify_no_egress()

    # Allowed in-boundary endpoints (Bifrost / local) must pass
    allowed_urls = [
        "http://localhost:8000/api/v1/bifrost",
        "http://bifrost.internal:8080/v1",
        "http://127.0.0.1:11434",
    ]
    for url in allowed_urls:
        adapter = ArtemisAdapter(bifrost_url=url)
        adapter.verify_no_egress()  # Should not raise


@pytest.mark.unit
def test_artemis_plan_compilation():
    """Verify AttackPlan compiles to valid ARTEMIS supervisor YAML with Bifrost config."""
    adapter = ArtemisAdapter(
        bifrost_url="http://bifrost.internal:8000/v1",
        virtual_key="artemis-key-test",
        rate_bucket="artemis-isolated",
    )

    step1 = AttackPlanStep(
        step_id="s1",
        technique_id="T1059.001",
        name="PowerShell Execution",
        description="Run base64 encoded powershell",
        target_asset="srv-dmz-01",
        command_or_action="powershell -enc ...",
    )
    plan = AttackPlan.create(
        environment_id="range-staging",
        objectives=["Compromise perimeter"],
        target_techniques=["T1059.001"],
        steps=[step1],
        seed=1337,
    )

    yaml_text = adapter.compile_plan_to_yaml(plan)
    parsed = yaml.safe_load(yaml_text)

    assert parsed["campaign"]["id"] == plan.plan_id
    assert parsed["campaign"]["environment_id"] == "range-staging"
    assert parsed["campaign"]["seed"] == 1337
    assert parsed["llm"]["base_url"] == "http://bifrost.internal:8000/v1/v1"
    assert parsed["llm"]["api_key"] == "artemis-key-test"
    assert parsed["llm"]["rate_bucket"] == "artemis-isolated"
    assert parsed["llm"]["max_retries"] == 1  # Conservative retry
    assert len(parsed["tasks"]) == 1
    assert parsed["tasks"][0]["technique_id"] == "T1059.001"


@pytest.mark.asyncio
async def test_artemis_execution_flow():
    """Verify execution returns action trace, telemetry, and rate-isolated spend."""
    adapter = ArtemisAdapter(
        bifrost_url="http://localhost:8000/bifrost",
        virtual_key="artemis-key",
        rate_bucket="artemis-bucket",
    )

    steps = [
        AttackPlanStep(
            step_id="step-1",
            technique_id="T1059.001",
            name="PowerShell probe",
            description="Probe host",
            target_asset="host-01",
            command_or_action="powershell.exe -c Get-Process",
        ),
        AttackPlanStep(
            step_id="step-2",
            technique_id="T1003",
            name="Credential Access",
            description="Dump credentials",
            target_asset="host-01",
            command_or_action="mimikatz.exe",
        ),
    ]
    plan = AttackPlan.create(
        environment_id="staging-range",
        objectives=["Test defense"],
        target_techniques=["T1059.001", "T1003"],
        steps=steps,
    )

    result = await adapter.execute(plan)

    assert result.status == ExecutionStatus.COMPLETED
    assert result.plan_id == plan.plan_id
    assert len(result.action_trace) == 2
    assert result.action_trace[0].technique_id == "T1059.001"
    assert result.action_trace[0].status == ActionStatus.SUCCESS
    assert len(result.captured_telemetry) == 2
    assert result.token_spend["virtual_key"] == "artemis-key"
    assert result.token_spend["rate_bucket"] == "artemis-bucket"
    assert result.token_spend["cost_usd"] > 0


@pytest.mark.asyncio
async def test_artemis_rejects_unauthorized_prod_environment():
    """Verify execution against unvetted production environment is refused."""
    adapter = ArtemisAdapter(bifrost_url="http://localhost:8000/bifrost")
    plan = AttackPlan.create(
        environment_id="production-banking-core",
        objectives=["Disrupt core"],
        target_techniques=["T1486"],
        steps=[],
    )

    with pytest.raises(UnauthorizedEnvironmentError):
        await adapter.execute(plan)
