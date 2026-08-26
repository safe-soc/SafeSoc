"""
SafeSOC — Incidents Router Tests
"""

import uuid
from datetime import datetime, timezone

import pytest

from app.core.enums import IncidentStatus, UserRole
from app.db.postgresql import get_db
from app.main import app
from app.models.endpoint import Endpoint
from app.models.incident import Incident, IncidentNote
from app.models.ti_cache import TICache
from app.models.user import User


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
    """Fake AsyncSession standing in for a real DB round-trip (mirrors tests/test_incidents.py)."""

    def __init__(
        self, existing_incidents=None, existing_notes=None, existing_users=None,
        existing_endpoints=None, existing_ti_cache=None,
    ):
        self.existing_incidents: list[Incident] = list(existing_incidents or [])
        self.existing_notes: list[IncidentNote] = list(existing_notes or [])
        self.existing_users: list[User] = list(existing_users or [])
        # SS-101: get_incident_evidence's Endpoint/TICache annotation
        # lookups route through this same fake session — empty by
        # default (no annotation available), same as a host/IP with no
        # row in the real tables.
        self.existing_endpoints: list[Endpoint] = list(existing_endpoints or [])
        self.existing_ti_cache: list[TICache] = list(existing_ti_cache or [])
        self.added: list = []

    async def execute(self, stmt, params=None):
        # select(IncidentNote)/select(User)/select(Endpoint)/select(TICache)
        # are routed to their own lists by inspecting what entity the
        # statement targets (mirrors tests/test_incidents.py).
        target = getattr(stmt, "column_descriptions", [{}])[0].get("type") if hasattr(stmt, "column_descriptions") else None
        if target is IncidentNote:
            return _FakeResult(self.existing_notes)
        if target is User:
            return _FakeResult(self.existing_users)
        if target is Endpoint:
            return _FakeResult(self.existing_endpoints)
        if target is TICache:
            return _FakeResult(self.existing_ti_cache)
        return _FakeResult(self.existing_incidents)

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        for obj in self.added:
            if isinstance(obj, Incident):
                # Simulate what a real flush assigns via server_default=func.now().
                if obj.created_at is None:
                    obj.created_at = datetime.now(timezone.utc)
                if obj.updated_at is None:
                    obj.updated_at = datetime.now(timezone.utc)
                if obj not in self.existing_incidents:
                    self.existing_incidents.append(obj)
            elif isinstance(obj, IncidentNote):
                if obj.id is None:
                    obj.id = uuid.uuid4()
                if obj.created_at is None:
                    obj.created_at = datetime.now(timezone.utc)
                if obj not in self.existing_notes:
                    self.existing_notes.append(obj)
        self.added = []

    async def refresh(self, obj):
        pass


def _seeded_incident(**overrides) -> Incident:
    """An Incident as if already round-tripped through the DB (created_at/updated_at populated)."""
    now = datetime.now(timezone.utc)
    fields = {
        "id": uuid.uuid4(),
        "tenant_id": uuid.uuid4(),
        "status": IncidentStatus.OPEN,
        "alert_ids": [],
        "created_at": now,
        "updated_at": now,
    }
    fields.update(overrides)
    return Incident(**fields)


@pytest.fixture
def db_session():
    """Wires a fresh fake DB session into the app for the duration of one test."""
    fake_session = _FakeSession()

    async def override_get_db():
        yield fake_session

    app.dependency_overrides[get_db] = override_get_db
    yield fake_session
    app.dependency_overrides.pop(get_db, None)


def test_create_incident_requires_authentication(client, db_session):
    response = client.post("/api/v1/incidents", json={"alert_ids": ["a1"]})
    assert response.status_code == 401


def test_create_incident_requires_analyst_role(client, db_session, make_auth_headers):
    headers = make_auth_headers(role=UserRole.VIEWER)

    response = client.post("/api/v1/incidents", json={"alert_ids": ["a1"]}, headers=headers)

    assert response.status_code == 403


def test_create_incident_returns_201_and_the_created_incident(client, db_session, make_auth_headers):
    tenant_id = uuid.uuid4()
    headers = make_auth_headers(tenant_id=tenant_id, role=UserRole.ANALYST)

    response = client.post("/api/v1/incidents", json={"alert_ids": ["a1", "a2"]}, headers=headers)

    assert response.status_code == 201
    body = response.json()
    assert body["tenant_id"] == str(tenant_id)
    assert body["status"] == "open"
    assert body["alert_ids"] == ["a1", "a2"]


def test_create_incident_defaults_to_no_alert_ids(client, db_session, make_auth_headers):
    headers = make_auth_headers(role=UserRole.ANALYST)

    response = client.post("/api/v1/incidents", json={}, headers=headers)

    assert response.status_code == 201
    assert response.json()["alert_ids"] == []


def test_list_incidents_is_readable_by_a_viewer(client, db_session, make_auth_headers):
    tenant_id = uuid.uuid4()
    db_session.existing_incidents = [
        _seeded_incident(tenant_id=tenant_id, alert_ids=["a1"]),
    ]
    headers = make_auth_headers(tenant_id=tenant_id, role=UserRole.VIEWER)

    response = client.get("/api/v1/incidents", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert len(body["incidents"]) == 1


def test_get_incident_returns_404_when_not_found(client, db_session, make_auth_headers):
    headers = make_auth_headers(role=UserRole.VIEWER)

    response = client.get(f"/api/v1/incidents/{uuid.uuid4()}", headers=headers)

    assert response.status_code == 404


def test_get_incident_returns_the_incident_when_it_exists(client, db_session, make_auth_headers):
    tenant_id = uuid.uuid4()
    incident = _seeded_incident(tenant_id=tenant_id, alert_ids=["a1"])
    db_session.existing_incidents = [incident]
    headers = make_auth_headers(tenant_id=tenant_id, role=UserRole.VIEWER)

    response = client.get(f"/api/v1/incidents/{incident.id}", headers=headers)

    assert response.status_code == 200
    assert response.json()["id"] == str(incident.id)


def test_transition_requires_analyst_role(client, db_session, make_auth_headers):
    incident = _seeded_incident()
    db_session.existing_incidents = [incident]
    headers = make_auth_headers(role=UserRole.VIEWER)

    response = client.post(
        f"/api/v1/incidents/{incident.id}/transitions", json={"to_status": "investigating"}, headers=headers
    )

    assert response.status_code == 403


def test_transition_returns_409_for_an_invalid_transition(client, db_session, make_auth_headers):
    tenant_id = uuid.uuid4()
    incident = _seeded_incident(tenant_id=tenant_id, status=IncidentStatus.RESOLVED)
    db_session.existing_incidents = [incident]
    headers = make_auth_headers(tenant_id=tenant_id, role=UserRole.ANALYST)

    response = client.post(
        f"/api/v1/incidents/{incident.id}/transitions", json={"to_status": "open"}, headers=headers
    )

    assert response.status_code == 409


def test_transition_returns_200_and_the_updated_incident(client, db_session, make_auth_headers):
    tenant_id = uuid.uuid4()
    incident = _seeded_incident(tenant_id=tenant_id)
    db_session.existing_incidents = [incident]
    headers = make_auth_headers(tenant_id=tenant_id, role=UserRole.ANALYST)

    response = client.post(
        f"/api/v1/incidents/{incident.id}/transitions", json={"to_status": "investigating"}, headers=headers
    )

    assert response.status_code == 200
    assert response.json()["status"] == "investigating"
    assert incident.status == IncidentStatus.INVESTIGATING


# ── SS-095: incident assignment ─────────────────────────────────

def test_assign_requires_authentication(client, db_session):
    incident = _seeded_incident()
    db_session.existing_incidents = [incident]

    response = client.post(
        f"/api/v1/incidents/{incident.id}/assign", json={"assignee_user_id": str(uuid.uuid4())}
    )

    assert response.status_code == 401


def test_assign_requires_analyst_role(client, db_session, make_auth_headers):
    incident = _seeded_incident()
    db_session.existing_incidents = [incident]
    headers = make_auth_headers(role=UserRole.VIEWER)

    response = client.post(
        f"/api/v1/incidents/{incident.id}/assign", json={"assignee_user_id": str(uuid.uuid4())}, headers=headers
    )

    assert response.status_code == 403


def test_assign_returns_200_and_the_assigned_incident(client, db_session, make_auth_headers):
    tenant_id = uuid.uuid4()
    incident = _seeded_incident(tenant_id=tenant_id)
    analyst = User(id=uuid.uuid4(), tenant_id=tenant_id, email="a@acme.example", password_hash="x", role=UserRole.ANALYST)
    db_session.existing_incidents = [incident]
    db_session.existing_users = [analyst]
    headers = make_auth_headers(tenant_id=tenant_id, role=UserRole.ANALYST)

    response = client.post(
        f"/api/v1/incidents/{incident.id}/assign", json={"assignee_user_id": str(analyst.id)}, headers=headers
    )

    assert response.status_code == 200
    assert response.json()["assigned_analyst_id"] == str(analyst.id)


def test_assign_returns_404_for_a_missing_incident(client, db_session, make_auth_headers):
    headers = make_auth_headers(role=UserRole.ANALYST)

    response = client.post(
        f"/api/v1/incidents/{uuid.uuid4()}/assign", json={"assignee_user_id": str(uuid.uuid4())}, headers=headers
    )

    assert response.status_code == 404


def test_assign_returns_404_for_an_assignee_that_does_not_exist(client, db_session, make_auth_headers):
    tenant_id = uuid.uuid4()
    incident = _seeded_incident(tenant_id=tenant_id)
    db_session.existing_incidents = [incident]
    db_session.existing_users = []  # no such user
    headers = make_auth_headers(tenant_id=tenant_id, role=UserRole.ANALYST)

    response = client.post(
        f"/api/v1/incidents/{incident.id}/assign", json={"assignee_user_id": str(uuid.uuid4())}, headers=headers
    )

    assert response.status_code == 404


# ── SS-037: post-creation alert linking + investigation notes ──


def test_link_alert_requires_analyst_role(client, db_session, make_auth_headers):
    incident = _seeded_incident()
    db_session.existing_incidents = [incident]
    headers = make_auth_headers(role=UserRole.VIEWER)

    response = client.post(f"/api/v1/incidents/{incident.id}/alerts", json={"alert_id": "a1"}, headers=headers)

    assert response.status_code == 403


def test_link_alert_adds_the_alert_id(client, db_session, make_auth_headers):
    tenant_id = uuid.uuid4()
    incident = _seeded_incident(tenant_id=tenant_id, alert_ids=["a1"])
    db_session.existing_incidents = [incident]
    headers = make_auth_headers(tenant_id=tenant_id, role=UserRole.ANALYST)

    response = client.post(f"/api/v1/incidents/{incident.id}/alerts", json={"alert_id": "a2"}, headers=headers)

    assert response.status_code == 200
    assert response.json()["alert_ids"] == ["a1", "a2"]


def test_link_alert_is_idempotent(client, db_session, make_auth_headers):
    tenant_id = uuid.uuid4()
    incident = _seeded_incident(tenant_id=tenant_id, alert_ids=["a1"])
    db_session.existing_incidents = [incident]
    headers = make_auth_headers(tenant_id=tenant_id, role=UserRole.ANALYST)

    response = client.post(f"/api/v1/incidents/{incident.id}/alerts", json={"alert_id": "a1"}, headers=headers)

    assert response.status_code == 200
    assert response.json()["alert_ids"] == ["a1"]


def test_add_note_requires_analyst_role(client, db_session, make_auth_headers):
    incident = _seeded_incident()
    db_session.existing_incidents = [incident]
    headers = make_auth_headers(role=UserRole.VIEWER)

    response = client.post(f"/api/v1/incidents/{incident.id}/notes", json={"body": "note"}, headers=headers)

    assert response.status_code == 403


def test_add_note_returns_201_with_author_and_timestamp(client, db_session, make_auth_headers):
    tenant_id = uuid.uuid4()
    incident = _seeded_incident(tenant_id=tenant_id)
    db_session.existing_incidents = [incident]
    headers = make_auth_headers(tenant_id=tenant_id, role=UserRole.ANALYST)

    response = client.post(
        f"/api/v1/incidents/{incident.id}/notes", json={"body": "Confirmed lateral movement."}, headers=headers
    )

    assert response.status_code == 201
    body = response.json()
    assert body["incident_id"] == str(incident.id)
    assert body["body"] == "Confirmed lateral movement."
    assert body["author_user_id"] is not None
    assert body["created_at"] is not None


def test_list_notes_is_readable_by_a_viewer(client, db_session, make_auth_headers):
    tenant_id = uuid.uuid4()
    incident = _seeded_incident(tenant_id=tenant_id)
    db_session.existing_incidents = [incident]
    db_session.existing_notes = [
        IncidentNote(
            id=uuid.uuid4(),
            incident_id=incident.id,
            author_user_id=uuid.uuid4(),
            body="First note.",
            created_at=datetime.now(timezone.utc),
        )
    ]
    headers = make_auth_headers(tenant_id=tenant_id, role=UserRole.VIEWER)

    response = client.get(f"/api/v1/incidents/{incident.id}/notes", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["body"] == "First note."


def test_notes_endpoints_return_404_for_a_missing_incident(client, db_session, make_auth_headers):
    headers = make_auth_headers(role=UserRole.ANALYST)

    response = client.post(f"/api/v1/incidents/{uuid.uuid4()}/notes", json={"body": "note"}, headers=headers)

    assert response.status_code == 404


# ── SS-099: unified incident investigation timeline ─────────────────
# get_alerts_by_ids hits OpenSearch and list_events hits the audit_log
# table via a real query this router-level _FakeSession doesn't model
# (see tests/test_incident_timeline.py for the service-level interleaving
# tests) — both are mocked here so these tests exercise only the HTTP
# layer: auth, 404 handling, and response shape.

@pytest.fixture(autouse=True)
def _mock_timeline_sources(monkeypatch):
    from unittest.mock import AsyncMock

    monkeypatch.setattr("app.services.incident_timeline.get_alerts_by_ids", AsyncMock(return_value=[]))
    monkeypatch.setattr("app.services.incident_timeline.list_events", AsyncMock(return_value=([], 0)))


def test_get_timeline_requires_authentication(client, db_session):
    response = client.get(f"/api/v1/incidents/{uuid.uuid4()}/timeline")
    assert response.status_code == 401


def test_get_timeline_is_readable_by_a_viewer(client, db_session, make_auth_headers):
    tenant_id = uuid.uuid4()
    incident = _seeded_incident(tenant_id=tenant_id)
    db_session.existing_incidents = [incident]
    headers = make_auth_headers(tenant_id=tenant_id, role=UserRole.VIEWER)

    response = client.get(f"/api/v1/incidents/{incident.id}/timeline", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["incident_id"] == str(incident.id)
    assert body["entries"] == []


def test_get_timeline_returns_404_for_a_missing_incident(client, db_session, make_auth_headers):
    headers = make_auth_headers(role=UserRole.VIEWER)

    response = client.get(f"/api/v1/incidents/{uuid.uuid4()}/timeline", headers=headers)

    assert response.status_code == 404


def test_get_timeline_returns_interleaved_entries(client, db_session, make_auth_headers, monkeypatch):
    from unittest.mock import AsyncMock

    tenant_id = uuid.uuid4()
    incident = _seeded_incident(tenant_id=tenant_id, alert_ids=["a1"])
    db_session.existing_incidents = [incident]
    db_session.existing_notes = [
        IncidentNote(
            id=uuid.uuid4(), incident_id=incident.id, author_user_id=uuid.uuid4(), body="First note.",
            created_at=datetime(2026, 8, 1, 12, 0, tzinfo=timezone.utc),
        )
    ]
    monkeypatch.setattr(
        "app.services.incident_timeline.get_alerts_by_ids",
        AsyncMock(return_value=[{"alert_id": "a1", "timestamp": "2026-08-01T10:00:00Z", "host_id": "H1"}]),
    )
    headers = make_auth_headers(tenant_id=tenant_id, role=UserRole.VIEWER)

    response = client.get(f"/api/v1/incidents/{incident.id}/timeline", headers=headers)

    assert response.status_code == 200
    entries = response.json()["entries"]
    assert [e["type"] for e in entries] == ["alert", "note"]


# ── SS-101: incident evidence explorer endpoint ──────────────────────
# get_alerts_by_ids hits OpenSearch and Endpoint/TICache lookups hit
# real queries this router-level _FakeSession doesn't model (see
# tests/test_incident_evidence.py for the service-level extraction
# tests) — get_alerts_by_ids is mocked here so these tests exercise
# only the HTTP layer: auth, 404 handling, and response shape.

@pytest.fixture(autouse=True)
def _mock_evidence_sources(monkeypatch):
    from unittest.mock import AsyncMock

    monkeypatch.setattr("app.services.incident_evidence.get_alerts_by_ids", AsyncMock(return_value=[]))


def test_get_evidence_requires_authentication(client, db_session):
    response = client.get(f"/api/v1/incidents/{uuid.uuid4()}/evidence")
    assert response.status_code == 401


def test_get_evidence_is_readable_by_a_viewer(client, db_session, make_auth_headers):
    tenant_id = uuid.uuid4()
    incident = _seeded_incident(tenant_id=tenant_id)
    db_session.existing_incidents = [incident]
    headers = make_auth_headers(tenant_id=tenant_id, role=UserRole.VIEWER)

    response = client.get(f"/api/v1/incidents/{incident.id}/evidence", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["incident_id"] == str(incident.id)
    assert body["hosts"] == []
    assert body["ips"] == []
    assert body["users"] == []
    assert body["cloud_resources"] == []


def test_get_evidence_returns_404_for_a_missing_incident(client, db_session, make_auth_headers):
    headers = make_auth_headers(role=UserRole.VIEWER)

    response = client.get(f"/api/v1/incidents/{uuid.uuid4()}/evidence", headers=headers)

    assert response.status_code == 404


def test_get_evidence_extracts_entities_from_real_alert_data(client, db_session, make_auth_headers, monkeypatch):
    from unittest.mock import AsyncMock

    tenant_id = uuid.uuid4()
    incident = _seeded_incident(tenant_id=tenant_id, alert_ids=["a1"])
    db_session.existing_incidents = [incident]
    monkeypatch.setattr(
        "app.services.incident_evidence.get_alerts_by_ids",
        AsyncMock(return_value=[{"host_id": "H1", "user": "alice", "source": "wazuh"}]),
    )
    headers = make_auth_headers(tenant_id=tenant_id, role=UserRole.VIEWER)

    response = client.get(f"/api/v1/incidents/{incident.id}/evidence", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["hosts"][0]["host_id"] == "H1"
    assert body["users"][0]["user"] == "alice"
