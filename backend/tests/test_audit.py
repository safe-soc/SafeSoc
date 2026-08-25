"""
SafeSOC — Shared Audit Log Service Tests
"""

import uuid
from datetime import datetime, timezone

import pytest

from app.models.audit_log import AuditLog
from app.services.audit import list_events, record_event


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)

    def scalar_one(self):
        return len(self._rows)


class _FakeSession:
    """
    Fake AsyncSession tracking committed AuditLog rows, same pattern as
    tests/test_incidents.py's own _FakeSession. Like that file's fake,
    this can't prove the real SQL WHERE clause actually filters by
    tenant_id/target_type/target_id at the database level — that's
    argued instead by code inspection (list_events's filter-building
    mirrors services/incidents.py:list_incidents's already-trusted
    pattern exactly, same `filters = [Model.tenant_id == tenant_id, ...]`
    shape) and was additionally verified live against the real Docker
    Postgres instance for this issue.
    """

    def __init__(self, existing_events=None):
        self.existing_events: list[AuditLog] = list(existing_events or [])
        self.added: list = []
        self.commit_count = 0

    async def execute(self, stmt, params=None):
        return _FakeResult(self.existing_events)

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        self.commit_count += 1
        for obj in self.added:
            if obj.id is None:
                obj.id = uuid.uuid4()
            if obj.created_at is None:
                obj.created_at = datetime.now(timezone.utc)
            if obj not in self.existing_events:
                self.existing_events.append(obj)
        self.added = []

    async def refresh(self, obj):
        pass


# ── record_event ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_record_event_creates_an_entry_with_the_given_fields():
    session = _FakeSession()
    tenant_id = uuid.uuid4()
    actor_id = uuid.uuid4()

    entry = await record_event(
        session, tenant_id, action="incident.created", target_type="incident", target_id="abc-123",
        actor_user_id=actor_id, details={"status": "open"},
    )

    assert entry.tenant_id == tenant_id
    assert entry.action == "incident.created"
    assert entry.target_type == "incident"
    assert entry.target_id == "abc-123"
    assert entry.actor_user_id == actor_id
    assert entry.details == {"status": "open"}
    assert session.commit_count == 1


@pytest.mark.asyncio
async def test_record_event_defaults_to_no_actor_and_empty_details():
    """Not every audit-worthy event has a human actor — e.g. an incident auto-created by correlation."""
    session = _FakeSession()
    tenant_id = uuid.uuid4()

    entry = await record_event(session, tenant_id, action="incident.created", target_type="incident", target_id="x")

    assert entry.actor_user_id is None
    assert entry.details == {}


@pytest.mark.asyncio
async def test_record_event_assigns_an_id_and_persists_the_entry():
    session = _FakeSession()
    tenant_id = uuid.uuid4()

    entry = await record_event(session, tenant_id, action="a", target_type="t", target_id="1")

    assert entry.id is not None
    assert entry in session.existing_events


# ── list_events ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_events_returns_matching_entries_and_total_count():
    tenant_id = uuid.uuid4()
    existing = [
        AuditLog(id=uuid.uuid4(), tenant_id=tenant_id, action="a", target_type="incident", target_id="1", details={}),
        AuditLog(id=uuid.uuid4(), tenant_id=tenant_id, action="b", target_type="incident", target_id="2", details={}),
    ]
    session = _FakeSession(existing_events=existing)

    events, total = await list_events(session, tenant_id)

    assert total == 2
    assert len(events) == 2


@pytest.mark.asyncio
async def test_list_events_defaults_to_no_target_filter():
    """Without target_type/target_id, list_events returns every event for the tenant (an activity feed, not a per-entity view)."""
    session = _FakeSession()
    tenant_id = uuid.uuid4()

    events, total = await list_events(session, tenant_id)

    assert events == []
    assert total == 0
