"""Tests for customer-owned detection overlay, promotion, and automatic demotion."""

import pytest
from core.detections.candidates import DetectionCandidate
from core.detections.overlay import CustomerOverlayService
from core.policies.schema import Policy, PolicyKind


def test_overlay_source_registered_and_searchable(tmp_path):
    """Verify customer overlay rules are searchable alongside detections domain."""
    overlay = CustomerOverlayService(storage_dir=tmp_path)
    cand = DetectionCandidate(
        candidate_id="cand-overlay-001",
        environment_id="staging-range",
        technique_id="T1047",
        rule_name="Customer WMI Lateral Movement Detection",
        rule_content="title: Customer WMI Lateral Movement Detection",
        rationale="Authored in loop",
    )

    overlay.promote(cand, actor="secops.analyst")

    # Search overlay
    results = overlay.search_detections(technique_id="T1047")
    assert len(results) == 1
    assert results[0]["source"] == "customer_overlay"
    assert results[0]["rule_id"] == "cand-overlay-001"
    assert results[0]["active"] is True


def test_promotion_requires_human_or_matching_policy(tmp_path):
    """Verify promote requires human actor or pre-authorized policy."""
    overlay = CustomerOverlayService(storage_dir=tmp_path)
    cand = DetectionCandidate(
        candidate_id="cand-overlay-002",
        environment_id="staging-range",
        technique_id="T1003",
        rule_name="Customer Credential Dumping Detection",
        rule_content="title: Credential Dumping",
        rationale="Authored in loop",
    )

    with pytest.raises(PermissionError, match="Promotion requires an authorized human actor"):
        overlay.promote(cand, actor="agent")

    # Policy with pre-authorization allows system promotion
    policy = Policy(
        id="pol-auto-promo",
        kind=PolicyKind.AUTONOMY,
        scope="loop_promotion",
        params={"pre_authorized_promotion": True},
        promoted_by="ciso",
    )
    rule = overlay.promote(cand, actor="system", autonomy_policy=policy)
    assert rule.active is True
    assert rule.rule_id == "cand-overlay-002"


def test_promoted_rule_exceeding_fp_threshold_automatically_demoted(tmp_path):
    """Verify a noisy rule exceeding false positive threshold is automatically demoted."""
    overlay = CustomerOverlayService(
        storage_dir=tmp_path,
        fp_count_threshold=3,
        fp_rate_threshold=0.50,
    )
    cand = DetectionCandidate(
        candidate_id="cand-noisy-001",
        environment_id="staging-range",
        technique_id="T1059",
        rule_name="Noisy PowerShell Rule",
        rule_content="title: Noisy Rule",
        rationale="Testing demotion",
    )

    rule = overlay.promote(cand, actor="john.analyst")
    assert rule.active is True

    # Record 1 TP and 1 FP
    overlay.record_feedback("cand-noisy-001", is_false_positive=False)
    overlay.record_feedback("cand-noisy-001", is_false_positive=True)
    assert rule.active is True

    # Record 2 more FPs (total FPs: 3 >= fp_count_threshold)
    overlay.record_feedback("cand-noisy-001", is_false_positive=True)
    overlay.record_feedback("cand-noisy-001", is_false_positive=True)

    # Must be automatically demoted
    assert rule.active is False
    assert rule.demoted_at is not None
    assert "exceeded false-positive threshold" in rule.demotion_reason

    # Inactive rules are excluded from normal search
    active_matches = overlay.search_detections(technique_id="T1059")
    assert len(active_matches) == 0

    # Found when include_inactive=True
    all_matches = overlay.search_detections(technique_id="T1059", include_inactive=True)
    assert len(all_matches) == 1
    assert all_matches[0]["active"] is False
