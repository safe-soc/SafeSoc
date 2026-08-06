"""
SafeSOC — Tenant/User/TICache Model Tests
"""

from datetime import datetime, timedelta, timezone

from app.core.config import settings
from app.core.enums import TIProvider, UserRole
from app.models import Base
from app.models.tenant import Tenant
from app.models.ti_cache import TICache, compute_expiry
from app.models.user import User


def test_tenant_and_user_tables_registered_on_metadata():
    assert "tenants" in Base.metadata.tables
    assert "users" in Base.metadata.tables
    assert "ti_cache" in Base.metadata.tables


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


# ── SS-024: TICache model ──────────────────────────────────────

def test_ti_cache_provider_column_uses_ti_provider_enum():
    provider_column = TICache.__table__.c.provider
    assert provider_column.type.enum_class is TIProvider


def test_ti_cache_has_composite_unique_constraint_on_indicator_and_provider():
    constraint = next(
        c for c in TICache.__table__.constraints if c.name == "uq_ti_cache_indicator_provider"
    )
    assert {col.name for col in constraint.columns} == {"indicator", "provider"}


def test_compute_expiry_reads_malicious_ttl_from_config_not_hardcoded():
    now = datetime.now(timezone.utc)

    expiry = compute_expiry(is_malicious=True, now=now)

    assert expiry == now + timedelta(seconds=settings.TI_CACHE_MALICIOUS_TTL)


def test_compute_expiry_reads_clean_ttl_from_config_not_hardcoded():
    now = datetime.now(timezone.utc)

    expiry = compute_expiry(is_malicious=False, now=now)

    assert expiry == now + timedelta(seconds=settings.TI_CACHE_CLEAN_TTL)


def test_compute_expiry_changes_when_config_value_changes(monkeypatch):
    """Proves the TTL genuinely comes from config, not a hardcoded constant."""
    monkeypatch.setattr(settings, "TI_CACHE_MALICIOUS_TTL", 12345)
    now = datetime.now(timezone.utc)

    expiry = compute_expiry(is_malicious=True, now=now)

    assert expiry == now + timedelta(seconds=12345)
