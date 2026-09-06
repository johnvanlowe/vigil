"""0.5.0 schema baseline

Revision ID: 0001_baseline_0_5_0
Revises: 
Create Date: 2026-09-06 00:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0001_baseline_0_5_0'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 0.5.0 baseline reflects the initialized database up through release 0.5.0 / 0.6.0.
    # On an existing installation, this baseline is stamped or acts as the root
    # for all subsequent Wave 1/2 migrations.
    pass


def downgrade() -> None:
    pass
