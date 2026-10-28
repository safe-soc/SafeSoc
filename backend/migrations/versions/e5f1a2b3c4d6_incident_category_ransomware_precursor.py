"""incident category: ransomware_precursor

Revision ID: e5f1a2b3c4d6
Revises: d3a1c9e7f2b4
Create Date: 2026-10-28 00:00:00.000000

Adds CorrelationPattern.RANSOMWARE_PRECURSOR to the native Postgres
enum behind incidents.category (created in 378c96369721). ALTER TYPE
... ADD VALUE can't run inside a transaction block on older Postgres,
and a new value can't be used in the transaction that added it, so it
runs in an autocommit block. IF NOT EXISTS keeps a re-run harmless.

Downgrade is a deliberate no-op: Postgres can't drop a value from an
enum type, and rebuilding the type would fail for any incident row
that already uses it. The extra value is harmless to older code.
"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = 'e5f1a2b3c4d6'
down_revision: Union[str, None] = 'd3a1c9e7f2b4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE incident_category ADD VALUE IF NOT EXISTS 'ransomware_precursor'")


def downgrade() -> None:
    # No-op by design: see the module docstring.
    pass
