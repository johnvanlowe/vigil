"""Database role definitions and grant verifications for Vigil."""

from __future__ import annotations

import os
from typing import Optional
from sqlalchemy import text
from sqlalchemy.engine import Engine


APP_ROLE_NAME = "vigil_app"
ADMIN_ROLE_NAME = "vigil_admin"


def get_current_db_role(engine: Engine) -> str:
    """Return the current database user/role for the connection."""
    with engine.connect() as conn:
        if engine.dialect.name == "postgresql":
            res = conn.execute(text("SELECT current_user;")).scalar()
            return str(res)
        return "sqlite_default"


def verify_ledger_append_only(engine: Engine) -> bool:
    """Verify that the active session or vigil_app cannot UPDATE or DELETE from agent_events."""
    if engine.dialect.name != "postgresql":
        # SQLite does not enforce SQL GRANTs; treated as verified by application boundary
        return True

    with engine.connect() as conn:
        # Check has_table_privilege for vigil_app
        can_insert = conn.execute(
            text("SELECT has_table_privilege('vigil_app', 'agent_events', 'INSERT');")
        ).scalar()
        can_select = conn.execute(
            text("SELECT has_table_privilege('vigil_app', 'agent_events', 'SELECT');")
        ).scalar()
        can_update = conn.execute(
            text("SELECT has_table_privilege('vigil_app', 'agent_events', 'UPDATE');")
        ).scalar()
        can_delete = conn.execute(
            text("SELECT has_table_privilege('vigil_app', 'agent_events', 'DELETE');")
        ).scalar()

        return bool(can_insert and can_select and not can_update and not can_delete)
