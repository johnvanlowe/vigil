"""Tests for typed response Action model, approval routing, and idempotency."""

from core.response.action import Action, ActionExecutor, ReversibilityClass


def test_irreversible_action_always_requires_approval():
    """Irreversible actions require approval even with 1.0 confidence."""
    executor = ActionExecutor()

    action = Action(
        action_id="act-1",
        action_type="wipe_endpoint",
        target="host-finance-01",
        confidence=1.0,  # Maximum confidence
        blast_radius="single_host",
        reversibility=ReversibilityClass.IRREVERSIBLE,
        rollback_plan="Restore from snapshot backup",
        idempotency_key="wipe-host-finance-01-20260906",
    )

    assert executor.requires_approval(action) is True


def test_reversible_action_respects_confidence_threshold():
    """Reversible action does not require approval if above threshold."""
    executor = ActionExecutor()

    # High confidence reversible action
    action_high = Action(
        action_id="act-2",
        action_type="isolate_host",
        target="host-02",
        confidence=0.95,
        blast_radius="single_host",
        reversibility=ReversibilityClass.REVERSIBLE,
        rollback_plan="Re-enable network adapter",
        idempotency_key="isolate-host-02",
    )
    assert executor.requires_approval(action_high) is False

    # Low confidence reversible action
    action_low = Action(
        action_id="act-3",
        action_type="isolate_host",
        target="host-03",
        confidence=0.75,
        blast_radius="single_host",
        reversibility=ReversibilityClass.REVERSIBLE,
        rollback_plan="Re-enable network adapter",
        idempotency_key="isolate-host-03",
    )
    assert executor.requires_approval(action_low) is True


def test_idempotency_key_deduplication():
    """Executing an action twice with the same idempotency key is deduplicated."""
    executor = ActionExecutor()

    action = Action(
        action_id="act-4",
        action_type="block_ip",
        target="198.51.100.42",
        confidence=0.99,
        blast_radius="edge_firewall",
        reversibility=ReversibilityClass.REVERSIBLE,
        rollback_plan="Unblock IP from edge firewall",
        idempotency_key="block-ip-198.51.100.42",
    )

    first_res = executor.execute_action(action)
    assert first_res["status"] == "executed"

    # Second execution with same idempotency key
    action2 = Action(
        action_id="act-5",
        action_type="block_ip",
        target="198.51.100.42",
        confidence=0.99,
        blast_radius="edge_firewall",
        reversibility=ReversibilityClass.REVERSIBLE,
        rollback_plan="Unblock IP from edge firewall",
        idempotency_key="block-ip-198.51.100.42",
    )
    second_res = executor.execute_action(action2)
    assert second_res["status"] == "deduplicated"
