"""
SafeSOC — Incident Investigation Timeline Service Tests (SS-099)
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from app.core.enums import IncidentStatus
from app.core.exceptions import IncidentNotFoundError
from app.models.audit_log import AuditLog
from app.models.incident import Incident, IncidentNote
from app.services.incident_timeline import get_incident_timeline


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)

    def scalar_one(self):
        return len(self._rows)

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None


class _FakeSession:
    """
    Fake AsyncSession standing in for get_incident/list_notes' real DB
    round-trip (mirrors tests/test_incidents.py's own fake). Only
    Incident/IncidentNote lookups route through here — get_alerts_by_ids
    and list_events (audit) are mocked directly at the module level
    below, since they don't go through this session's execute() at all
    (get_alerts_by_ids hits OpenSearch; list_events uses its own
    AuditLog-shaped query this fake doesn't need to model).
    """

    def __init__(self, existing_incidents=None, existing_notes=None):
        self.existing_incidents: list[Incident] = list(existing_incidents or [])
        self.existing_notes: list[IncidentNote] = list(existing_notes or [])

    async def execute(self, stmt, params=None):
        target = getattr(stmt, "column_descriptions", [{}])[0].get("type") if hasattr(stmt, "column_descriptions") else None
        if target is IncidentNote:
            return _FakeResult(self.existing_notes)
        return _FakeResult(self.existing_incidents)


def _incident(**overrides) -> Incident:
    fields = {"id": uuid.uuid4(), "tenant_id": uuid.uuid4(), "status": IncidentStatus.OPEN, "alert_ids": []}
    fields.update(overrides)
    return Incident(**fields)


def _mock_sources(monkeypatch, alerts=None, audit_events=None):
    monkeypatch.setattr(
        "app.services.incident_timeline.get_alerts_by_ids", AsyncMock(return_value=alerts or [])
    )
    monkeypatch.setattr(
        "app.services.incident_timeline.list_events", AsyncMock(return_value=(audit_events or [], 0))
    )


@pytest.mark.asyncio
async def test_raises_not_found_for_a_missing_incident(monkeypatch):
    _mock_sources(monkeypatch)
    session = _FakeSession()

    with pytest.raises(IncidentNotFoundError):
        await get_incident_timeline(session, uuid.uuid4(), uuid.uuid4())


@pytest.mark.asyncio
async def test_interleaves_alerts_audit_events_and_notes_by_real_timestamp(monkeypatch):
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id=tenant_id, alert_ids=["a1"])
    session = _FakeSession(existing_incidents=[incident])

    alerts = [{"alert_id": "a1", "timestamp": "2026-08-01T10:00:00Z", "host_id": "H1"}]
    audit_events = [
        AuditLog(
            id=uuid.uuid4(), tenant_id=tenant_id, actor_user_id=None, action="incident.created",
            target_type="incident", target_id=str(incident.id), details={"source": "manual"},
            created_at=datetime(2026, 8, 1, 9, 0, tzinfo=timezone.utc),
        )
    ]
    note = IncidentNote(
        id=uuid.uuid4(), incident_id=incident.id, author_user_id=uuid.uuid4(), body="Confirmed.",
        created_at=datetime(2026, 8, 1, 11, 0, tzinfo=timezone.utc),
    )
    session.existing_notes = [note]
    _mock_sources(monkeypatch, alerts=alerts, audit_events=audit_events)

    entries = await get_incident_timeline(session, tenant_id, incident.id)

    assert [e.type for e in entries] == ["audit", "alert", "note"]
    assert entries[0].timestamp < entries[1].timestamp < entries[2].timestamp


@pytest.mark.asyncio
async def test_audit_entry_data_carries_action_actor_and_details(monkeypatch):
    tenant_id = uuid.uuid4()
    actor_id = uuid.uuid4()
    incident = _incident(tenant_id=tenant_id)
    session = _FakeSession(existing_incidents=[incident])
    audit_events = [
        AuditLog(
            id=uuid.uuid4(), tenant_id=tenant_id, actor_user_id=actor_id, action="incident.status_transitioned",
            target_type="incident", target_id=str(incident.id), details={"from_status": "open", "to_status": "investigating"},
            created_at=datetime.now(timezone.utc),
        )
    ]
    _mock_sources(monkeypatch, audit_events=audit_events)

    entries = await get_incident_timeline(session, tenant_id, incident.id)

    assert entries[0].data == {
        "action": "incident.status_transitioned",
        "actor_user_id": str(actor_id),
        "details": {"from_status": "open", "to_status": "investigating"},
    }


@pytest.mark.asyncio
async def test_audit_entry_actor_is_none_for_system_generated_events(monkeypatch):
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id=tenant_id)
    session = _FakeSession(existing_incidents=[incident])
    audit_events = [
        AuditLog(
            id=uuid.uuid4(), tenant_id=tenant_id, actor_user_id=None, action="incident.created",
            target_type="incident", target_id=str(incident.id), details={}, created_at=datetime.now(timezone.utc),
        )
    ]
    _mock_sources(monkeypatch, audit_events=audit_events)

    entries = await get_incident_timeline(session, tenant_id, incident.id)

    assert entries[0].data["actor_user_id"] is None


@pytest.mark.asyncio
async def test_note_entry_data_carries_id_author_and_body(monkeypatch):
    tenant_id = uuid.uuid4()
    author_id = uuid.uuid4()
    incident = _incident(tenant_id=tenant_id)
    session = _FakeSession(existing_incidents=[incident])
    note = IncidentNote(
        id=uuid.uuid4(), incident_id=incident.id, author_user_id=author_id, body="Lateral movement confirmed.",
        created_at=datetime.now(timezone.utc),
    )
    session.existing_notes = [note]
    _mock_sources(monkeypatch)

    entries = await get_incident_timeline(session, tenant_id, incident.id)

    assert entries[0].data == {"id": str(note.id), "author_user_id": str(author_id), "body": "Lateral movement confirmed."}


@pytest.mark.asyncio
async def test_an_alert_with_no_parseable_timestamp_is_omitted_gracefully(monkeypatch):
    """AC: unresolvable/malformed alert data degrades gracefully rather than failing the whole timeline."""
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id=tenant_id, alert_ids=["a1", "a2"])
    session = _FakeSession(existing_incidents=[incident])
    alerts = [
        {"alert_id": "a1", "timestamp": "not-a-timestamp"},
        {"alert_id": "a2"},  # no timestamp field at all
    ]
    _mock_sources(monkeypatch, alerts=alerts)

    entries = await get_incident_timeline(session, tenant_id, incident.id)

    assert entries == []


@pytest.mark.asyncio
async def test_an_alert_missing_from_opensearch_is_simply_absent(monkeypatch):
    """
    get_alerts_by_ids itself only returns alerts that actually exist
    (SS-099's db/opensearch.py addition) — an incident referencing an
    unresolvable alert_id just gets fewer alert entries, no error.
    """
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id=tenant_id, alert_ids=["missing-1"])
    session = _FakeSession(existing_incidents=[incident])
    _mock_sources(monkeypatch, alerts=[])

    entries = await get_incident_timeline(session, tenant_id, incident.id)

    assert entries == []


@pytest.mark.asyncio
async def test_empty_incident_produces_an_empty_timeline(monkeypatch):
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id=tenant_id)
    session = _FakeSession(existing_incidents=[incident])
    _mock_sources(monkeypatch)

    entries = await get_incident_timeline(session, tenant_id, incident.id)

    assert entries == []
