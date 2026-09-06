"""0002_ledger_grants: enforce INSERT and SELECT only on agent_events for app role

Revision ID: 0002_ledger_grants
Revises: 0001_baseline_0_5_0
Create Date: 2026-09-06 00:01:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = '0002_ledger_grants'
down_revision: Union[str, None] = '0001_baseline_0_5_0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name
    if dialect == "postgresql":
        # Create vigil_app role if it does not already exist
        op.execute(
            """
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vigil_app') THEN
                    CREATE ROLE vigil_app WITH LOGIN;
                END IF;
            END
            $$;
            """
        )
        # Grant only SELECT and INSERT on agent_events
        op.execute("GRANT SELECT, INSERT ON agent_events TO vigil_app;")
        op.execute("REVOKE UPDATE, DELETE, TRUNCATE ON agent_events FROM vigil_app;")


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("REVOKE SELECT, INSERT ON agent_events FROM vigil_app;")
