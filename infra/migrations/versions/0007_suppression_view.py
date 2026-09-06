"""0007_suppression_view: create suppression_candidates view over dismiss verdicts

Revision ID: 0007_suppression_view
Revises: 0005_artifacts
Create Date: 2026-09-06 00:07:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = '0007_suppression_view'
down_revision: Union[str, None] = '0006_coverage_view'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    if conn.dialect.name == "postgresql":
        op.execute(
            """
            CREATE OR REPLACE VIEW suppression_candidates AS
            SELECT
                payload->>'reason' AS match_reason,
                count(*) AS dismissal_count,
                max(ts) AS last_dismissed_at,
                (array_agg(payload->>'finding_id'))[1] AS sample_finding_id
            FROM agent_events
            WHERE kind = 'verdict'
              AND payload->>'action' = 'dismiss'
              AND payload->>'reason' IS NOT NULL
            GROUP BY payload->>'reason'
            HAVING count(*) >= 3;
            """
        )
    else:
        op.execute(
            """
            CREATE VIEW IF NOT EXISTS suppression_candidates AS
            SELECT
                json_extract(payload, '$.reason') AS match_reason,
                count(*) AS dismissal_count,
                max(ts) AS last_dismissed_at,
                json_extract(payload, '$.finding_id') AS sample_finding_id
            FROM agent_events
            WHERE kind = 'verdict'
              AND json_extract(payload, '$.action') = 'dismiss'
              AND json_extract(payload, '$.reason') IS NOT NULL
            GROUP BY json_extract(payload, '$.reason')
            HAVING count(*) >= 3;
            """
        )


def downgrade() -> None:
    op.execute("DROP VIEW IF EXISTS suppression_candidates;")
