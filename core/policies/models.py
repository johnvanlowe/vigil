"""SQLAlchemy model for the policies table, isolated in its own domain module."""

from __future__ import annotations

from sqlalchemy import Column, DateTime, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import JSON

from core.storage.models import Base
from core.time import utcnow


class PolicyModel(Base):
    """Database representation of a governance policy."""

    __tablename__ = "policies"

    id = Column(String(64), primary_key=True)
    kind = Column(String(32), nullable=False, index=True)
    scope = Column(String(255), nullable=False, index=True)
    params = Column(JSONB().with_variant(JSON(), "sqlite"), nullable=False)
    ttl = Column(Integer, nullable=True)
    promoted_by = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utcnow, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=True, onupdate=utcnow)

    def __repr__(self) -> str:
        return f"<PolicyModel(id={self.id!r}, kind={self.kind!r}, scope={self.scope!r})>"
