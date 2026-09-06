"""0004_policies: create policies table for governance

Revision ID: 0004_policies
Revises: 0003_ledger_hash
Create Date: 2026-09-06 00:03:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = '0004_policies'
down_revision: Union[str, None] = '0003_ledger_hash'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    tables = inspector.get_table_names()

    if 'policies' not in tables:
        dialect = conn.dialect.name
        json_type = postgresql.JSONB if dialect == "postgresql" else sa.JSON
        op.create_table(
            'policies',
            sa.Column('id', sa.String(length=64), primary_key=True),
            sa.Column('kind', sa.String(length=32), nullable=False),
            sa.Column('scope', sa.String(length=255), nullable=False),
            sa.Column('params', json_type, nullable=False),
            sa.Column('ttl', sa.Integer(), nullable=True),
            sa.Column('promoted_by', sa.String(length=255), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        )
        op.create_index('idx_policies_kind_scope', 'policies', ['kind', 'scope'])


def downgrade() -> None:
    op.drop_table('policies')
