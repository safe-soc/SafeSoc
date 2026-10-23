"""alert dismiss reason and note

Revision ID: d3a1c9e7f2b4
Revises: b4eb11fb1ac5
Create Date: 2026-10-23 00:00:00.000000

Additive: two nullable columns on alert_annotations, so existing
dismissed rows simply have no recorded reason. dismiss_reason is plain
VARCHAR (DismissReason values, validated in the API), not a Postgres
enum type, so downgrade only has to drop the columns.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd3a1c9e7f2b4'
down_revision: Union[str, None] = 'b4eb11fb1ac5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('alert_annotations', sa.Column('dismiss_reason', sa.String(length=32), nullable=True))
    op.add_column('alert_annotations', sa.Column('dismiss_note', sa.String(length=500), nullable=True))


def downgrade() -> None:
    op.drop_column('alert_annotations', 'dismiss_note')
    op.drop_column('alert_annotations', 'dismiss_reason')
