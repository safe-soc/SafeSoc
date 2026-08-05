"""
SafeSOC — Tenant/User Model Tests
"""

from app.core.enums import UserRole
from app.models import Base
from app.models.tenant import Tenant
from app.models.user import User


def test_tenant_and_user_tables_registered_on_metadata():
    assert "tenants" in Base.metadata.tables
    assert "users" in Base.metadata.tables


def test_user_role_column_uses_user_role_enum():
    role_column = User.__table__.c.role
    assert role_column.type.enum_class is UserRole


def test_users_table_has_composite_unique_constraint_on_tenant_id_and_email():
    constraint = next(
        c for c in User.__table__.constraints if c.name == "uq_users_tenant_id_email"
    )
    assert {col.name for col in constraint.columns} == {"tenant_id", "email"}


def test_users_tenant_id_is_foreign_key_to_tenants_id():
    fk_targets = {fk.target_fullname for fk in User.__table__.c.tenant_id.foreign_keys}
    assert fk_targets == {"tenants.id"}
