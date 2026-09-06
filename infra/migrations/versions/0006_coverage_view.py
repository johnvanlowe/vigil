"""0006_coverage_view: create coverage view over reconstruction and promotion events

Revision ID: 0006_coverage_view
Revises: 0005_artifacts
Create Date: 2026-09-06 00:06:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = '0006_coverage_view'
down_revision: Union[str, None] = '0005_artifacts'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    if conn.dialect.name == "postgresql":
        op.execute(
            """
            CREATE OR REPLACE VIEW coverage AS
            SELECT
                COALESCE(payload->>'environment_id', 'default') AS environment_id,
                COALESCE(payload->>'technique_id', 'unknown') AS technique_id,
                COALESCE((payload->>'cycle_number')::integer, 1) AS cycle_number,
                kind,
                COALESCE(payload->>'verdict', CASE WHEN kind = 'promotion' THEN 'promoted' ELSE 'unknown' END) AS verdict,
                payload->>'matching_rules' AS matching_rules,
                ts AS event_time
            FROM agent_events
            WHERE kind IN ('reconstruction', 'promotion');
            """
        )
    else:
        op.execute(
            """
            CREATE VIEW IF NOT EXISTS coverage AS
            SELECT
                COALESCE(json_extract(payload, '$.environment_id'), 'default') AS environment_id,
                COALESCE(json_extract(payload, '$.technique_id'), 'unknown') AS technique_id,
                COALESCE(json_extract(payload, '$.cycle_number'), 1) AS cycle_number,
                kind,
                COALESCE(json_extract(payload, '$.verdict'), CASE WHEN kind = 'promotion' THEN 'promoted' ELSE 'unknown' END) AS verdict,
                json_extract(payload, '$.matching_rules') AS matching_rules,
                ts AS event_time
            FROM agent_events
            WHERE kind IN ('reconstruction', 'promotion');
            """
        )


def downgrade() -> None:
    op.execute("DROP VIEW IF EXISTS coverage;")
