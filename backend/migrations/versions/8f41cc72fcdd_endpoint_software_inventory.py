"""endpoint software inventory (demo simulation)

Revision ID: 8f41cc72fcdd
Revises: fc72a841e85c
Create Date: 2026-08-26 18:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8f41cc72fcdd'
down_revision: Union[str, None] = 'fc72a841e85c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'endpoint_software',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('tenant_id', sa.Uuid(), nullable=False),
        sa.Column('host_id', sa.String(length=255), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('version', sa.String(length=64), nullable=False),
        sa.Column(
            'category',
            sa.Enum(
                'operating_system', 'browser', 'productivity', 'runtime', 'remote_admin', 'security', 'other',
                name='software_category',
            ),
            nullable=False,
        ),
        sa.Column('vulnerabilities', sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('tenant_id', 'host_id', 'name', name='uq_endpoint_software_tenant_host_name'),
    )
    # No separate (tenant_id, host_id) index: the unique constraint above
    # already provides one via its leading columns.


def downgrade() -> None:
    op.drop_table('endpoint_software')
    sa.Enum(name='software_category').drop(op.get_bind(), checkfirst=True)
