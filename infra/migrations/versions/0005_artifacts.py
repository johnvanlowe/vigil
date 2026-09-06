"""0005_artifacts: create hash-addressed artifacts table

Revision ID: 0005_artifacts
Revises: 0004_policies
Create Date: 2026-09-06 00:04:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = '0005_artifacts'
down_revision: Union[str, None] = '0004_policies'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    tables = inspector.get_table_names()

    if 'artifacts' not in tables:
        op.create_table(
            'artifacts',
            sa.Column('hash', sa.String(length=64), primary_key=True),
            sa.Column('kind', sa.String(length=64), nullable=False),
            sa.Column('run_id', sa.String(length=64), nullable=True),
            sa.Column('supersedes', sa.String(length=64), nullable=True),
            sa.Column('bytes', sa.LargeBinary(), nullable=False),
            sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        )
        op.create_index('idx_artifacts_run_id', 'artifacts', ['run_id'])
        op.create_index('idx_artifacts_kind', 'artifacts', ['kind'])


def downgrade() -> None:
    op.drop_table('artifacts')
