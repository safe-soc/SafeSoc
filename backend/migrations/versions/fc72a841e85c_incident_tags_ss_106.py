"""incident tags (SS-106)

Revision ID: fc72a841e85c
Revises: a95704406124
Create Date: 2026-08-26 06:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'fc72a841e85c'
down_revision: Union[str, None] = 'a95704406124'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'incidents',
        sa.Column('tags', sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    )


def downgrade() -> None:
    op.drop_column('incidents', 'tags')
