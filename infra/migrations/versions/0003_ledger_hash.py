"""0003_ledger_hash: add prev_hash and event_hash to agent_events

Revision ID: 0003_ledger_hash
Revises: 0002_ledger_grants
Create Date: 2026-09-06 00:02:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = '0003_ledger_hash'
down_revision: Union[str, None] = '0002_ledger_grants'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add columns if not already present
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    columns = [c['name'] for c in inspector.get_columns('agent_events')]

    if 'prev_hash' not in columns:
        op.add_column('agent_events', sa.Column('prev_hash', sa.String(length=64), nullable=True))
    if 'event_hash' not in columns:
        op.add_column('agent_events', sa.Column('event_hash', sa.String(length=64), nullable=True))


def downgrade() -> None:
    op.drop_column('agent_events', 'event_hash')
    op.drop_column('agent_events', 'prev_hash')
