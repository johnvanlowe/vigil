"""Hash-addressed artifact storage service."""

from __future__ import annotations

import hashlib
from typing import Optional
from sqlalchemy import select

from core.artifacts.models import ArtifactModel
from contextlib import contextmanager

from core.artifacts.models import ArtifactModel
from core.storage.connection import get_db_manager
from core.storage.ledger import append_agent_event


class ArtifactService:
    """Service providing content-addressed immutable artifact storage."""

    def __init__(self, db=None, session_factory=None):
        self._db = db or get_db_manager()
        self._session_factory = session_factory

    @contextmanager
    def session_scope(self):
        if self._session_factory:
            sess = self._session_factory()
            try:
                yield sess
                sess.commit()
            except Exception:
                sess.rollback()
                raise
            finally:
                sess.close()
        else:
            if self._db._session_factory is None:
                try:
                    self._db.initialize()
                except Exception:
                    pass
            with self._db.session_scope() as sess:
                yield sess

    def put(
        self,
        data: bytes | str,
        kind: str,
        run_id: Optional[str] = None,
        supersedes: Optional[str] = None,
        emit_ledger_event: bool = True,
    ) -> str:
        """Store artifact content addressed by SHA-256 hash.

        Identical bytes produce the same hash without duplicate writes.
        """
        raw_bytes = data.encode("utf-8") if isinstance(data, str) else data
        artifact_hash = hashlib.sha256(raw_bytes).hexdigest()

        with self.session_scope() as session:
            existing = session.get(ArtifactModel, artifact_hash)
            if not existing:
                row = ArtifactModel(
                    hash=artifact_hash,
                    kind=kind,
                    run_id=run_id,
                    supersedes=supersedes,
                    bytes=raw_bytes,
                )
                session.add(row)

        if emit_ledger_event and run_id:
            try:
                append_agent_event(
                    run_id=run_id,
                    kind="agent_event",
                    payload={
                        "schema_version": 1,
                        "action": "artifact_stored",
                        "artifact_hash": artifact_hash,
                        "kind": kind,
                        "supersedes": supersedes,
                    },
                    run_kind="compose",
                )
            except Exception:
                pass

        return artifact_hash

    def get(self, artifact_hash: str) -> Optional[bytes]:
        """Retrieve the exact bytes of an artifact by its SHA-256 hash."""
        with self.session_scope() as session:
            row = session.get(ArtifactModel, artifact_hash)
            if row:
                return bytes(row.bytes)
            return None


# Global helper functions for convenience
_default_service = ArtifactService()

def put(data: bytes | str, kind: str, run_id: Optional[str] = None, supersedes: Optional[str] = None) -> str:
    return _default_service.put(data=data, kind=kind, run_id=run_id, supersedes=supersedes)

def get(artifact_hash: str) -> Optional[bytes]:
    return _default_service.get(artifact_hash)
