"""Tests for hash-addressed artifacts storage and retrieval."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.artifacts.models import ArtifactModel
from core.artifacts.service import ArtifactService


@pytest.fixture
def artifact_service():
    engine = create_engine("sqlite:///:memory:")
    ArtifactModel.__table__.create(engine)
    SessionLocal = sessionmaker(bind=engine)
    return ArtifactService(session_factory=SessionLocal)


def test_artifacts_put_and_get_roundtrip(artifact_service):
    """Verify storing content and retrieving exact bytes by hash."""
    content = b"VIGIL_REPORT_SCORECARD_PAYLOAD_12345"
    h1 = artifact_service.put(data=content, kind="scorecard", run_id="run-test-artifact", emit_ledger_event=False)

    assert len(h1) == 64
    retrieved = artifact_service.get(h1)
    assert retrieved == content


def test_identical_bytes_produce_same_hash_idempotently(artifact_service):
    """Identical bytes produce the same hash without failure."""
    content = b"REPRODUCIBLE_EVIDENCE_BYTES"
    h1 = artifact_service.put(content, kind="evidence", emit_ledger_event=False)
    h2 = artifact_service.put(content, kind="evidence", emit_ledger_event=False)

    assert h1 == h2


def test_superseding_artifact_chain(artifact_service):
    """Verify that a superseding artifact references its predecessor hash."""
    v1_content = b"REPORT_DRAFT_1"
    h1 = artifact_service.put(v1_content, kind="report", emit_ledger_event=False)

    v2_content = b"REPORT_FINAL_2"
    h2 = artifact_service.put(v2_content, kind="report", supersedes=h1, emit_ledger_event=False)

    assert h1 != h2
    assert artifact_service.get(h1) == v1_content
    assert artifact_service.get(h2) == v2_content
