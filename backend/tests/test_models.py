"""
SafeSOC — Tenant/User/TICache/Incident Model Tests
"""

import uuid
from datetime import datetime, timedelta, timezone

from app.core.config import settings
from app.core.enums import IncidentStatus, TIProvider, UserRole
from app.models import Base
from app.models.incident import Incident, IncidentStateTransition
from app.models.tenant import Tenant
from app.models.ti_cache import TICache, compute_expiry
from app.models.user import User


def test_tenant_and_user_tables_registered_on_metadata():
    assert "tenants" in Base.metadata.tables
    assert "users" in Base.metadata.tables
    assert "ti_cache" in Base.metadata.tables
    assert "incidents" in Base.metadata.tables
    assert "incident_state_transitions" in Base.metadata.tables


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


# ── SS-035: Incident model (Milestone 7 pull-forward, unblocks SS-031) ──

def test_incident_status_column_uses_incident_status_enum():
    status_column = Incident.__table__.c.status
    assert status_column.type.enum_class is IncidentStatus


def test_incident_status_defaults_to_open():
    # The column-level default is applied at flush, not bare instantiation
    # (same as User.role's default) — inspect the column metadata instead
    # of a live, un-flushed instance.
    assert Incident.__table__.c.status.default.arg == IncidentStatus.OPEN


def test_incident_tenant_id_is_foreign_key_to_tenants_id():
    fk_targets = {fk.target_fullname for fk in Incident.__table__.c.tenant_id.foreign_keys}
    assert fk_targets == {"tenants.id"}


def test_incident_assigned_analyst_id_is_nullable_foreign_key_to_users_id():
    column = Incident.__table__.c.assigned_analyst_id
    assert column.nullable is True
    assert {fk.target_fullname for fk in column.foreign_keys} == {"users.id"}


def test_incident_alert_ids_stores_a_list_of_alert_ids():
    incident = Incident(tenant_id=uuid.uuid4(), alert_ids=["alert-1", "alert-2", "alert-3"])
    assert incident.alert_ids == ["alert-1", "alert-2", "alert-3"]


def test_incident_state_transition_foreign_keys_target_incidents_and_users():
    incident_fk = {fk.target_fullname for fk in IncidentStateTransition.__table__.c.incident_id.foreign_keys}
    user_fk = {fk.target_fullname for fk in IncidentStateTransition.__table__.c.changed_by_user_id.foreign_keys}
    assert incident_fk == {"incidents.id"}
    assert user_fk == {"users.id"}


def test_incident_state_transition_from_status_is_nullable_for_initial_creation():
    """The very first transition (creation) has no prior status."""
    column = IncidentStateTransition.__table__.c.from_status
    assert column.nullable is True


def test_incident_state_transition_to_status_is_required():
    column = IncidentStateTransition.__table__.c.to_status
    assert column.nullable is False


def test_incident_state_transition_records_timestamp_and_acting_user():
    """
    Schema-level proof of the audit requirement: a transition row can
    hold everything "every state transition is recorded with timestamp
    + acting user" requires. The orchestration that calls this on every
    real transition is SS-036, not built here.
    """
    incident_id = uuid.uuid4()
    user_id = uuid.uuid4()
    transition = IncidentStateTransition(
        incident_id=incident_id,
        from_status=IncidentStatus.OPEN,
        to_status=IncidentStatus.INVESTIGATING,
        changed_by_user_id=user_id,
    )

    assert transition.incident_id == incident_id
    assert transition.from_status == IncidentStatus.OPEN
    assert transition.to_status == IncidentStatus.INVESTIGATING
    assert transition.changed_by_user_id == user_id
    # created_at is server_default=func.now() -- populated on flush, not
    # on bare construction; asserting the column itself carries a default
    # is what's testable without a live DB round-trip here.
    assert IncidentStateTransition.__table__.c.created_at.server_default is not None


def test_incident_transitions_relationship_is_ordered_by_created_at():
    relationship_prop = Incident.__mapper__.relationships["transitions"]
    assert relationship_prop.order_by is not None
