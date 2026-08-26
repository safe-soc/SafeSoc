"""alert annotations (SS-107)

Revision ID: a95704406124
Revises: 9c14b2e6a5d0
Create Date: 2026-08-26 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a95704406124'
down_revision: Union[str, None] = '9c14b2e6a5d0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'alert_annotations',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('tenant_id', sa.Uuid(), nullable=False),
        sa.Column('alert_id', sa.String(length=255), nullable=False),
        sa.Column('acknowledged', sa.Boolean(), nullable=False),
        sa.Column('dismissed', sa.Boolean(), nullable=False),
        sa.Column('updated_by_user_id', sa.Uuid(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
        sa.ForeignKeyConstraint(['updated_by_user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('tenant_id', 'alert_id', name='uq_alert_annotations_tenant_id_alert_id'),
    )


def downgrade() -> None:
    op.drop_table('alert_annotations')
