"""Tests for canonical verdict recording on findings."""

import pytest
from core.findings.verdicts import VerdictAction, record_verdict
from core.metrics.registry import get_metrics


def test_record_verdict_confirm():
    """Verify recording a confirm action emits a verdict event and increments metrics."""
    metrics = get_metrics()
    before_count = metrics.verdict_total.labels(action="confirm", source="ui")._value.get()

    verdict = record_verdict(
        finding_id="find-101",
        action=VerdictAction.CONFIRM,
        actor="analyst_bob",
        source="ui",
    )

    assert verdict["schema_version"] == 1
    assert verdict["finding_id"] == "find-101"
    assert verdict["action"] == "confirm"
    assert verdict["actor"] == "analyst_bob"

    after_count = metrics.verdict_total.labels(action="confirm", source="ui")._value.get()
    assert after_count == before_count + 1


def test_record_verdict_dismiss_requires_reason():
    """Dismissing a finding strictly requires a non-empty reason."""
    with pytest.raises(ValueError, match="strictly requires an explanatory reason"):
        record_verdict(
            finding_id="find-102",
            action=VerdictAction.DISMISS,
            actor="analyst_alice",
            reason="",
        )

    # With reason succeeds
    verdict = record_verdict(
        finding_id="find-102",
        action=VerdictAction.DISMISS,
        actor="analyst_alice",
        reason="Known internal vulnerability scanner benign traffic",
    )
    assert verdict["action"] == "dismiss"
    assert verdict["reason"] == "Known internal vulnerability scanner benign traffic"


def test_record_verdict_reject_requires_reason():
    """Rejecting an action proposal strictly requires a non-empty reason."""
    with pytest.raises(ValueError, match="strictly requires an explanatory reason"):
        record_verdict(
            finding_id="find-103",
            action=VerdictAction.REJECT,
            actor="analyst_alice",
            reason=None,
        )


def test_record_verdict_escalate_and_edit_severity():
    """Escalating and changing severity records the update correctly."""
    verdict = record_verdict(
        finding_id="find-104",
        action=VerdictAction.EDIT_SEVERITY,
        actor="analyst_charlie",
        new_severity="critical",
    )
    assert verdict["action"] == "edit_severity"
    assert verdict["new_severity"] == "critical"
