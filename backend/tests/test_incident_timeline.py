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


# ── SOAR lifecycle events on the timeline (Phase 3.5) ───────────────
#
# SOAR audit rows are written against the run/action they describe
# (target_type "soar_playbook_run" / "soar_action_execution"), never
# against the incident — so the timeline resolves this incident's own
# run/action ids and scopes the audit query to those. These cover that
# the events arrive, that they're scoped, and that the near-
# simultaneous pairs don't read as duplicates.


def _soar_event(tenant_id, action: str, target_type: str, target_id, minute: int, details=None) -> AuditLog:
    return AuditLog(
        id=uuid.uuid4(), tenant_id=tenant_id, actor_user_id=None, action=action,
        target_type=target_type, target_id=str(target_id), details=details or {},
        created_at=datetime(2026, 8, 1, 10, minute, tzinfo=timezone.utc),
    )


def _mock_soar_sources(monkeypatch, *, run_ids, action_ids, incident_events=(), run_events=(), action_events=()):
    """Mocks the timeline's three audit reads separately, keyed on the target_type each one asks for."""
    monkeypatch.setattr("app.services.incident_timeline.get_alerts_by_ids", AsyncMock(return_value=[]))
    monkeypatch.setattr(
        "app.services.incident_timeline.list_incident_audit_target_ids",
        AsyncMock(return_value=(run_ids, action_ids)),
    )
    seen_calls: list[dict] = []

    async def fake_list_events(db, tenant_id, **kwargs):
        seen_calls.append(kwargs)
        by_type = {
            "incident": list(incident_events),
            "soar_playbook_run": list(run_events),
            "soar_action_execution": list(action_events),
        }
        return by_type.get(kwargs.get("target_type"), []), 0

    monkeypatch.setattr("app.services.incident_timeline.list_events", fake_list_events)
    return seen_calls


@pytest.mark.asyncio
async def test_soar_lifecycle_events_appear_on_the_incident_timeline(monkeypatch):
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id=tenant_id)
    session = _FakeSession(existing_incidents=[incident])
    run_id, action_id = uuid.uuid4(), uuid.uuid4()
    _mock_soar_sources(
        monkeypatch,
        run_ids=[str(run_id)],
        action_ids=[str(action_id)],
        run_events=[
            _soar_event(tenant_id, "soar.playbook.triggered", "soar_playbook_run", run_id, 0, {"playbook_id": "pb-x"}),
            _soar_event(tenant_id, "soar.action.approved", "soar_playbook_run", run_id, 3, {"action_type": "isolate_endpoint"}),
        ],
        action_events=[
            _soar_event(tenant_id, "soar.action.started", "soar_action_execution", action_id, 4),
            _soar_event(tenant_id, "soar.action.succeeded", "soar_action_execution", action_id, 5),
            _soar_event(tenant_id, "soar.action.verified", "soar_action_execution", action_id, 6),
        ],
    )

    entries = await get_incident_timeline(session, tenant_id, incident.id)

    actions = [e.data["action"] for e in entries]
    assert actions == [
        "soar.playbook.triggered",
        "soar.action.approved",
        "soar.action.started",
        "soar.action.succeeded",
        "soar.action.verified",
    ]
    assert all(e.type == "audit" for e in entries)


@pytest.mark.asyncio
async def test_soar_events_are_scoped_to_this_incidents_own_runs_and_actions(monkeypatch):
    """
    The isolation property: the audit query is narrowed to the run/
    action ids resolved from THIS incident, so another incident's (or
    another tenant's) SOAR events can't be pulled into this timeline.
    """
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id=tenant_id)
    session = _FakeSession(existing_incidents=[incident])
    run_ids = [str(uuid.uuid4())]
    action_ids = [str(uuid.uuid4()), str(uuid.uuid4())]
    seen_calls = _mock_soar_sources(monkeypatch, run_ids=run_ids, action_ids=action_ids)

    await get_incident_timeline(session, tenant_id, incident.id)

    run_call = next(c for c in seen_calls if c.get("target_type") == "soar_playbook_run")
    action_call = next(c for c in seen_calls if c.get("target_type") == "soar_action_execution")
    assert run_call["target_ids"] == run_ids
    assert action_call["target_ids"] == action_ids
    # The incident-scoped read is untouched — still a single target_id, never widened.
    incident_call = next(c for c in seen_calls if c.get("target_type") == "incident")
    assert incident_call["target_id"] == str(incident.id)
    assert "target_ids" not in incident_call


@pytest.mark.asyncio
async def test_near_simultaneous_soar_pairs_are_not_shown_twice(monkeypatch):
    """
    soar.playbook_run.created and soar.playbook.triggered describe one
    moment, as do soar.action.queued and soar.action.started. Only one
    of each reaches the narrative, so the timeline doesn't stutter.
    """
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id=tenant_id)
    session = _FakeSession(existing_incidents=[incident])
    run_id, action_id = uuid.uuid4(), uuid.uuid4()
    _mock_soar_sources(
        monkeypatch,
        run_ids=[str(run_id)],
        action_ids=[str(action_id)],
        run_events=[
            _soar_event(tenant_id, "soar.playbook_run.created", "soar_playbook_run", run_id, 0),
            _soar_event(tenant_id, "soar.playbook.triggered", "soar_playbook_run", run_id, 0),
            _soar_event(tenant_id, "soar.action.queued", "soar_playbook_run", run_id, 1),
        ],
        action_events=[_soar_event(tenant_id, "soar.action.started", "soar_action_execution", action_id, 1)],
    )

    entries = await get_incident_timeline(session, tenant_id, incident.id)

    assert [e.data["action"] for e in entries] == ["soar.playbook.triggered", "soar.action.started"]


@pytest.mark.asyncio
async def test_a_skipped_action_is_surfaced_so_the_omission_is_visible(monkeypatch):
    """Phase 3.5's whole point: an action that never ran says so, in the place an analyst reads."""
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id=tenant_id)
    session = _FakeSession(existing_incidents=[incident])
    run_id = uuid.uuid4()
    _mock_soar_sources(
        monkeypatch,
        run_ids=[str(run_id)],
        action_ids=[],
        run_events=[
            _soar_event(
                tenant_id, "soar.action.skipped", "soar_playbook_run", run_id, 1,
                {"action_type": "enrich_indicator", "reason": "required_evidence_unavailable", "detail": "primary_ip"},
            )
        ],
    )

    entries = await get_incident_timeline(session, tenant_id, incident.id)

    assert len(entries) == 1
    assert entries[0].data["action"] == "soar.action.skipped"
    assert entries[0].data["details"]["reason"] == "required_evidence_unavailable"


@pytest.mark.asyncio
async def test_an_incident_with_no_soar_activity_issues_no_soar_audit_queries(monkeypatch):
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id=tenant_id)
    session = _FakeSession(existing_incidents=[incident])
    seen_calls = _mock_soar_sources(monkeypatch, run_ids=[], action_ids=[])

    entries = await get_incident_timeline(session, tenant_id, incident.id)

    assert entries == []
    assert [c.get("target_type") for c in seen_calls] == ["incident"]


@pytest.mark.asyncio
async def test_a_soar_read_failure_still_returns_the_rest_of_the_timeline(monkeypatch):
    """SOAR is one contributor to this narrative, not a prerequisite for it."""
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id=tenant_id)
    session = _FakeSession(existing_incidents=[incident])
    incident_event = _soar_event(tenant_id, "incident.created", "incident", incident.id, 0)
    _mock_soar_sources(monkeypatch, run_ids=[], action_ids=[], incident_events=[incident_event])
    monkeypatch.setattr(
        "app.services.incident_timeline.list_incident_audit_target_ids",
        AsyncMock(side_effect=RuntimeError("soar tables unavailable")),
    )

    entries = await get_incident_timeline(session, tenant_id, incident.id)

    assert [e.data["action"] for e in entries] == ["incident.created"]


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
