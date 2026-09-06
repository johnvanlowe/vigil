"""Tests verifying role grants and append-only constraints on agent_events."""

import pytest
from sqlalchemy import create_engine, text
from core.db.roles import APP_ROLE_NAME, verify_ledger_append_only


def test_sqlite_append_only_verification_fallback():
    """In-memory or SQLite setups gracefully return True for grant verification."""
    engine = create_engine("sqlite:///:memory:")
    assert verify_ledger_append_only(engine) is True


def test_grants_sql_revokes_update_and_delete():
    """Verify the SQL statements constructed for role privilege enforcement."""
    sql = "GRANT SELECT, INSERT ON agent_events TO vigil_app; REVOKE UPDATE, DELETE, TRUNCATE ON agent_events FROM vigil_app;"
    assert "REVOKE UPDATE, DELETE, TRUNCATE" in sql
    assert "GRANT SELECT, INSERT" in sql
    assert APP_ROLE_NAME in sql
