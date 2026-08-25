"""incident category and confidence (SS-094)

Revision ID: 378c96369721
Revises: 401e54761a11
Create Date: 2026-08-25 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '378c96369721'
down_revision: Union[str, None] = '401e54761a11'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_INCIDENT_CATEGORY_ENUM = sa.Enum(
    'credential_brute_force', 'successful_compromise', 'recon_to_exploitation',
    'privilege_escalation', 'data_exfiltration', 'lateral_movement',
    name='incident_category',
)


def upgrade() -> None:
    _INCIDENT_CATEGORY_ENUM.create(op.get_bind(), checkfirst=True)
    op.add_column('incidents', sa.Column('category', _INCIDENT_CATEGORY_ENUM, nullable=True))
    op.add_column('incidents', sa.Column('confidence', sa.Float(), nullable=True))


def downgrade() -> None:
    op.drop_column('incidents', 'confidence')
    op.drop_column('incidents', 'category')
    _INCIDENT_CATEGORY_ENUM.drop(op.get_bind(), checkfirst=True)
