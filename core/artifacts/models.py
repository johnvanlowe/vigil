"""SQLAlchemy model for the hash-addressed artifacts table."""

from __future__ import annotations

from sqlalchemy import Column, DateTime, LargeBinary, String, func
from core.storage.models import Base
from core.time import utcnow


class ArtifactModel(Base):
    """Database representation of an immutable, hash-addressed artifact."""

    __tablename__ = "artifacts"

    hash = Column(String(64), primary_key=True)
    kind = Column(String(64), nullable=False, index=True)
    run_id = Column(String(64), nullable=True, index=True)
    supersedes = Column(String(64), nullable=True)
    bytes = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, server_default=func.now())

    def __repr__(self) -> str:
        return f"<ArtifactModel(hash={self.hash[:8]}..., kind={self.kind!r})>"
