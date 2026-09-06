"""Tests for deterministic CISO attestation reports and artifact generation."""

import hashlib
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.artifacts.models import ArtifactModel
from core.artifacts.service import ArtifactService
from core.ledger.hash import compute_event_hash, GENESIS_HASH
from core.reports.attestation import build_attestation_report, parse_period, fold_ledger_events
from core.cli.attest import run_attestation_cli


@pytest.fixture
def in_memory_artifacts():
    engine = create_engine("sqlite:///:memory:")
    ArtifactModel.__table__.create(engine)
    Session = sessionmaker(bind=engine)
    return Session, ArtifactService(session_factory=Session)


def make_sample_ledger_chain():
    """Construct an untampered sequence of ledger events."""
    events = []
    prev = GENESIS_HASH

    raw_events = [
        ("stage_completed", {"stage": "triage", "actor": "agent", "spend_usd": 0.05}),
        ("stage_completed", {"stage": "triage", "actor": "human", "spend_usd": 0.0}),
        ("stage_completed", {"stage": "investigation", "actor": "agent", "spend_usd": 0.12}),
        ("verdict_recorded", {"verdict": "true_positive", "confirmed": True, "overturned": False}),
        ("action_executed", {"action": "quarantine_host", "status": "executed"}),
        (
            "policy_change",
            {
                "policy_id": "pol-sla-001",
                "kind": "sla",
                "actor": "ciso_alice",
                "direction": "tighten",
            },
        ),
        ("red_run_executed", {"scenario": "redrun_v1", "coverage_delta": 0.15}),
        ("detection_promoted", {"rule_id": "sigma-proc-001"}),
    ]

    for i, (kind, payload) in enumerate(raw_events):
        h = compute_event_hash(prev, payload)
        events.append(
            {
                "seq": i,
                "prev_hash": prev,
                "event_hash": h,
                "kind": kind,
                "payload": payload,
                "ts": f"2026-11-0{i+1}T12:00:00Z",
            }
        )
        prev = h

    return events


def test_parse_period_quarter():
    """Verify standard quarter conversion into UTC time range."""
    f, t, ident = parse_period(quarter="2026Q4")
    assert ident == "2026Q4"
    assert f.month == 10 and f.day == 1 and f.year == 2026
    assert t.month == 12 and t.day == 31 and t.year == 2026


def test_attestation_determinism(in_memory_artifacts):
    """Verify that two runs over the same period produce identical artifact hashes."""
    Session, art_svc = in_memory_artifacts
    events = make_sample_ledger_chain()

    res1 = run_attestation_cli(
        quarter="2026Q4",
        session_factory=Session,
        events_override=events,
    )
    res2 = run_attestation_cli(
        quarter="2026Q4",
        session_factory=Session,
        events_override=events,
    )

    assert res1["json_hash"] is not None
    assert res1["pdf_hash"] is not None
    # Crucial test requirement: two runs over the same period produce identical hashes
    assert res1["json_hash"] == res2["json_hash"]
    assert res1["pdf_hash"] == res2["pdf_hash"]
    assert res1["json_bytes"] == res2["json_bytes"]
    assert res1["pdf_bytes"] == res2["pdf_bytes"]

    # Verify retrieval from artifact service
    stored_json = art_svc.get(res1["json_hash"])
    stored_pdf = art_svc.get(res1["pdf_hash"])
    assert stored_json == res1["json_bytes"]
    assert stored_pdf == res1["pdf_bytes"]


def test_attestation_folds_and_policy_changes(in_memory_artifacts):
    """Verify metrics folding, ledger verification, and policy change recording."""
    Session, art_svc = in_memory_artifacts
    events = make_sample_ledger_chain()

    res = run_attestation_cli(
        quarter="2026Q4",
        session_factory=Session,
        events_override=events,
    )
    rep = res["report"]

    # Ledger verification result
    assert rep["ledger_verification"]["valid"] is True
    assert rep["ledger_verification"]["status"] == "VALID"
    assert rep["ledger_verification"]["events_verified"] == len(events)

    # Work share calculation (2 agent stages, 1 human stage = 66.67% agent)
    assert rep["work_share"]["total_completed_stages"] == 3
    assert rep["work_share"]["by_actor"]["agent"] == 2
    assert rep["work_share"]["by_actor"]["human"] == 1
    assert rep["work_share"]["agent_percentage"] == 66.67

    # Spend calculation ($0.05 + $0.12 = $0.17)
    assert rep["spend"]["total_spend_usd"] == 0.17

    # Governance: Policy changes listed with actor and direction
    assert len(rep["governance"]["policy_changes"]) == 1
    p_change = rep["governance"]["policy_changes"][0]
    assert p_change["policy_id"] == "pol-sla-001"
    assert p_change["actor"] == "ciso_alice"
    assert p_change["direction"] == "tighten"

    # Red run and promotion
    assert rep["offensive_eval"]["red_runs_evaluated"] == 1
    assert rep["offensive_eval"]["detections_promoted"] == 1
