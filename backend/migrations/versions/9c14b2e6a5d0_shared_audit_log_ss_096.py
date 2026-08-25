"""shared audit log (SS-096)

Revision ID: 9c14b2e6a5d0
Revises: 378c96369721
Create Date: 2026-08-25 00:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9c14b2e6a5d0'
down_revision: Union[str, None] = '378c96369721'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'audit_log',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('tenant_id', sa.Uuid(), nullable=False),
        sa.Column('actor_user_id', sa.Uuid(), nullable=True),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('target_type', sa.String(length=50), nullable=False),
        sa.Column('target_id', sa.String(length=255), nullable=False),
        sa.Column('details', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id'], ),
        sa.ForeignKeyConstraint(['actor_user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_audit_log_tenant_target', 'audit_log', ['tenant_id', 'target_type', 'target_id'])
    op.create_index('ix_audit_log_tenant_created', 'audit_log', ['tenant_id', 'created_at'])


def downgrade() -> None:
    op.drop_index('ix_audit_log_tenant_created', table_name='audit_log')
    op.drop_index('ix_audit_log_tenant_target', table_name='audit_log')
    op.drop_table('audit_log')
