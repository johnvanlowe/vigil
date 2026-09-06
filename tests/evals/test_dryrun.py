"""Tests for unattended dry run and scorecard artifact emission."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.artifacts.models import Base as ArtifactBase
from core.artifacts.service import ArtifactService
from core.cli.dryrun import run_dryrun
from core.evals.scorecard import Scorecard


@pytest.fixture
def in_memory_session():
    engine = create_engine("sqlite:///:memory:")
    from core.artifacts.models import ArtifactModel
    ArtifactModel.__table__.create(engine)
    Session = sessionmaker(bind=engine)
    return Session


def test_dryrun_runs_unattended_and_emits_scorecard(in_memory_session):
    """Verify dryrun runs against redrun_v1 and produces a hash-addressed scorecard artifact."""
    card = run_dryrun(
        scenario="redrun_v1",
        provider="frontier",
        session_factory=in_memory_session,
    )

    assert isinstance(card, Scorecard)
    assert card.scenario == "redrun_v1"
    assert card.disposition == "contained_and_hardened"
    assert card.artifact_hash is not None
    assert len(card.artifact_hash) == 64  # SHA-256

    # Verify gates met
    assert "reconstruction_schema_v1" in card.gates_met
    assert "telemetry_replay" in card.gates_met

    # Verify SOCBench baseline comparison
    assert card.socbench.socbench_baseline_mtta_seconds == 480
    assert card.socbench.vigil_containment_rate > card.socbench.socbench_baseline_containment_rate
    assert card.socbench.speedup_factor > 1.0

    # Verify artifact retrieval from service produces identical content
    art_service = ArtifactService(session_factory=in_memory_session)
    stored_bytes = art_service.get(card.artifact_hash)
    assert stored_bytes is not None
    assert card.run_id.encode("utf-8") in stored_bytes


def test_dryrun_ollama_provider_delta_notes(in_memory_session):
    """Verify dry run with Ollama provider notes delta and zero API dollar cost."""
    card = run_dryrun(
        scenario="redrun_v1",
        provider="ollama",
        session_factory=in_memory_session,
    )

    assert card.provider == "ollama"
    assert card.total_cost_usd == 0.0
    assert "Ollama" in card.socbench.notes
    assert "zero external cost" in card.socbench.notes
