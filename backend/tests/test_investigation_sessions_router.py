"""
SafeSOC — Investigation Sessions Router Tests
HTTP-layer wiring: authentication, role enforcement, and request/
response shape. Business logic and authorization (tenant isolation,
session-vs-incident scoping, confirmed/hypothesis provenance) is
covered directly against services/investigation_session.py in
test_investigation_session.py — these tests mock that service and
verify the router calls it correctly and shapes its response, mirroring
test_endpoints_router.py's own precedent for mocking a service function
imported into a router module.
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from app.core.enums import FindingCategory, FindingOrigin, InvestigationActionStatus, UserRole
from app.core.exceptions import IncidentNotFoundError, InvestigationSessionNotFoundError
from app.db.postgresql import get_db
from app.main import app
from app.mcp.tools import IncidentNarrativeDataOutput
from app.models.investigation_session import InvestigationAction, InvestigationFinding, InvestigationNote, InvestigationSession, InvestigationTurn
from app.routers.v1 import investigation_sessions as router_module


class _FakeSession:
    async def execute(self, *args, **kwargs):
        raise AssertionError("the service layer is mocked in these tests — no query should reach the fake db session")

    async def commit(self):
        pass

    async def refresh(self, obj):
        pass


@pytest.fixture
def db_session():
    fake_session = _FakeSession()

    async def override_get_db():
        yield fake_session

    app.dependency_overrides[get_db] = override_get_db
    yield fake_session
    app.dependency_overrides.pop(get_db, None)


def _session_row(incident_id=None, created_by=None):
    return InvestigationSession(id=uuid.uuid4(), incident_id=incident_id or uuid.uuid4(), created_by_user_id=created_by or uuid.uuid4(), created_at=datetime.now(timezone.utc))


def _evidence_data():
    return IncidentNarrativeDataOutput(incident_id=uuid.uuid4(), events=[], hosts=[], ips=[], users=[], cloud_resources=[], mitre_techniques=[], confidence=None)


# ── POST /sessions (start) ───────────────────────────────────────────

def test_start_session_requires_authentication(client, db_session):
    response = client.post(f"/api/v1/incidents/{uuid.uuid4()}/investigation/sessions")
    assert response.status_code == 401


def test_start_session_requires_analyst_role(client, db_session, make_auth_headers):
    headers = make_auth_headers(role=UserRole.VIEWER)
    response = client.post(f"/api/v1/incidents/{uuid.uuid4()}/investigation/sessions", headers=headers)
    assert response.status_code == 403


def test_start_session_returns_201_and_the_created_session(client, db_session, make_auth_headers, monkeypatch):
    incident_id = uuid.uuid4()
    tenant_id = uuid.uuid4()
    created = _session_row(incident_id=incident_id)
    mock_create = AsyncMock(return_value=created)
    monkeypatch.setattr(router_module.investigation_session_service, "create_session", mock_create)
    headers = make_auth_headers(tenant_id=tenant_id, role=UserRole.ANALYST)

    response = client.post(f"/api/v1/incidents/{incident_id}/investigation/sessions", headers=headers)

    assert response.status_code == 201
    assert response.json()["id"] == str(created.id)
    assert response.json()["incident_id"] == str(incident_id)
    mock_create.assert_called_once()
    assert mock_create.call_args.args[1] == tenant_id  # tenant_id comes from the JWT, not a request body


def test_start_session_propagates_incident_not_found_as_404(client, db_session, make_auth_headers, monkeypatch):
    monkeypatch.setattr(router_module.investigation_session_service, "create_session", AsyncMock(side_effect=IncidentNotFoundError(uuid.uuid4())))
    headers = make_auth_headers(role=UserRole.ANALYST)

    response = client.post(f"/api/v1/incidents/{uuid.uuid4()}/investigation/sessions", headers=headers)

    assert response.status_code == 404


# ── GET /sessions (list) ──────────────────────────────────────────────

def test_list_sessions_requires_authentication(client, db_session):
    response = client.get(f"/api/v1/incidents/{uuid.uuid4()}/investigation/sessions")
    assert response.status_code == 401


def test_list_sessions_is_readable_by_a_viewer(client, db_session, make_auth_headers, monkeypatch):
    incident_id = uuid.uuid4()
    sessions = [_session_row(incident_id=incident_id), _session_row(incident_id=incident_id)]
    monkeypatch.setattr(router_module.investigation_session_service, "list_sessions", AsyncMock(return_value=sessions))
    headers = make_auth_headers(role=UserRole.VIEWER)

    response = client.get(f"/api/v1/incidents/{incident_id}/investigation/sessions", headers=headers)

    assert response.status_code == 200
    assert len(response.json()) == 2


# ── GET /sessions/{id} (detail) ───────────────────────────────────────

def test_get_session_detail_rejects_a_session_from_another_incident_with_404(client, db_session, make_auth_headers, monkeypatch):
    """The router-level manifestation of the core security property: a session_id alone never resolves without matching its incident_id."""
    monkeypatch.setattr(router_module.investigation_session_service, "get_session_state", AsyncMock(side_effect=InvestigationSessionNotFoundError(uuid.uuid4())))
    headers = make_auth_headers(role=UserRole.VIEWER)

    response = client.get(f"/api/v1/incidents/{uuid.uuid4()}/investigation/sessions/{uuid.uuid4()}", headers=headers)

    assert response.status_code == 404


def test_get_session_detail_returns_evidence_turns_findings_actions_notes(client, db_session, make_auth_headers, monkeypatch):
    incident_id = uuid.uuid4()
    session = _session_row(incident_id=incident_id)
    turn = InvestigationTurn(id=uuid.uuid4(), session_id=session.id, asked_by_user_id=uuid.uuid4(), question="q", answer="a", is_fallback=False, created_at=datetime.now(timezone.utc))
    finding = InvestigationFinding(
        id=uuid.uuid4(), session_id=session.id, text="Host confirmed", category=FindingCategory.CONFIRMED, origin=FindingOrigin.ANALYST,
        created_by_user_id=uuid.uuid4(), confirmed_by_user_id=uuid.uuid4(), confirmed_at=datetime.now(timezone.utc),
        created_at=datetime.now(timezone.utc), updated_at=datetime.now(timezone.utc),
    )
    action = InvestigationAction(id=uuid.uuid4(), session_id=session.id, description="Pull logs", status=InvestigationActionStatus.OPEN, created_by_user_id=uuid.uuid4(), created_at=datetime.now(timezone.utc))
    note = InvestigationNote(id=uuid.uuid4(), session_id=session.id, author_user_id=uuid.uuid4(), body="note text", created_at=datetime.now(timezone.utc))
    monkeypatch.setattr(
        router_module.investigation_session_service, "get_session_state",
        AsyncMock(return_value=(session, _evidence_data(), [turn], [finding], [action], [note])),
    )
    headers = make_auth_headers(role=UserRole.VIEWER)

    response = client.get(f"/api/v1/incidents/{incident_id}/investigation/sessions/{session.id}", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["turns"][0]["question"] == "q"
    assert body["findings"][0]["category"] == "confirmed"
    assert body["actions"][0]["description"] == "Pull logs"
    assert body["notes"][0]["body"] == "note text"
    assert "hosts" in body["evidence"]


# ── POST /sessions/{id}/ask ───────────────────────────────────────────

def test_ask_requires_analyst_role(client, db_session, make_auth_headers):
    headers = make_auth_headers(role=UserRole.VIEWER)
    response = client.post(
        f"/api/v1/incidents/{uuid.uuid4()}/investigation/sessions/{uuid.uuid4()}/ask", json={"question": "what happened?"}, headers=headers
    )
    assert response.status_code == 403


def test_ask_returns_the_grounded_answer(client, db_session, make_auth_headers, monkeypatch):
    incident_id, session_id = uuid.uuid4(), uuid.uuid4()
    turn = InvestigationTurn(id=uuid.uuid4(), session_id=session_id, asked_by_user_id=uuid.uuid4(), question="Which host was involved?", answer="DEMO-CRITICAL-01.", is_fallback=False, created_at=datetime.now(timezone.utc))
    mock_ask = AsyncMock(return_value=turn)
    monkeypatch.setattr(router_module.investigation_session_service, "ask_question", mock_ask)
    headers = make_auth_headers(role=UserRole.ANALYST)

    response = client.post(f"/api/v1/incidents/{incident_id}/investigation/sessions/{session_id}/ask", json={"question": "Which host was involved?"}, headers=headers)

    assert response.status_code == 200
    assert response.json()["turn"]["answer"] == "DEMO-CRITICAL-01."
    assert response.json()["turn"]["is_fallback"] is False
    mock_ask.assert_called_once()
    assert mock_ask.call_args.args[4] == "Which host was involved?"


def test_ask_for_a_session_belonging_to_a_different_incident_404s(client, db_session, make_auth_headers, monkeypatch):
    monkeypatch.setattr(router_module.investigation_session_service, "ask_question", AsyncMock(side_effect=InvestigationSessionNotFoundError(uuid.uuid4())))
    headers = make_auth_headers(role=UserRole.ANALYST)

    response = client.post(f"/api/v1/incidents/{uuid.uuid4()}/investigation/sessions/{uuid.uuid4()}/ask", json={"question": "q"}, headers=headers)

    assert response.status_code == 404


# ── findings ───────────────────────────────────────────────────────

def test_create_finding_requires_analyst_role(client, db_session, make_auth_headers):
    headers = make_auth_headers(role=UserRole.VIEWER)
    response = client.post(
        f"/api/v1/incidents/{uuid.uuid4()}/investigation/sessions/{uuid.uuid4()}/findings",
        json={"text": "x", "category": "hypothesis"}, headers=headers,
    )
    assert response.status_code == 403


def test_create_finding_is_readable_back_with_ai_suggested_origin_when_that_was_passed_through(client, db_session, make_auth_headers, monkeypatch):
    session_id = uuid.uuid4()
    finding = InvestigationFinding(
        id=uuid.uuid4(), session_id=session_id, text="possible valid-account abuse", category=FindingCategory.HYPOTHESIS, origin=FindingOrigin.ANALYST,
        created_by_user_id=uuid.uuid4(), created_at=datetime.now(timezone.utc), updated_at=datetime.now(timezone.utc),
    )
    monkeypatch.setattr(router_module.investigation_session_service, "create_finding", AsyncMock(return_value=finding))
    headers = make_auth_headers(role=UserRole.ANALYST)

    response = client.post(
        f"/api/v1/incidents/{uuid.uuid4()}/investigation/sessions/{session_id}/findings",
        json={"text": "possible valid-account abuse", "category": "hypothesis"}, headers=headers,
    )

    assert response.status_code == 201
    assert response.json()["category"] == "hypothesis"
    assert response.json()["origin"] == "analyst"


def test_update_finding_confirms_it(client, db_session, make_auth_headers, monkeypatch):
    session_id, finding_id = uuid.uuid4(), uuid.uuid4()
    actor_id = uuid.uuid4()
    updated = InvestigationFinding(
        id=finding_id, session_id=session_id, text="x", category=FindingCategory.CONFIRMED, origin=FindingOrigin.AI_SUGGESTED,
        confirmed_by_user_id=actor_id, confirmed_at=datetime.now(timezone.utc), created_at=datetime.now(timezone.utc), updated_at=datetime.now(timezone.utc),
    )
    mock_update = AsyncMock(return_value=updated)
    monkeypatch.setattr(router_module.investigation_session_service, "update_finding_category", mock_update)
    headers = make_auth_headers(role=UserRole.ANALYST)

    response = client.patch(
        f"/api/v1/incidents/{uuid.uuid4()}/investigation/sessions/{session_id}/findings/{finding_id}",
        json={"category": "confirmed"}, headers=headers,
    )

    assert response.status_code == 200
    assert response.json()["category"] == "confirmed"
    assert response.json()["confirmed_by_user_id"] == str(actor_id)


# ── actions ────────────────────────────────────────────────────────

def test_create_action_requires_analyst_role(client, db_session, make_auth_headers):
    headers = make_auth_headers(role=UserRole.VIEWER)
    response = client.post(
        f"/api/v1/incidents/{uuid.uuid4()}/investigation/sessions/{uuid.uuid4()}/actions", json={"description": "x"}, headers=headers
    )
    assert response.status_code == 403


def test_update_action_marks_it_completed(client, db_session, make_auth_headers, monkeypatch):
    action_id = uuid.uuid4()
    updated = InvestigationAction(
        id=action_id, session_id=uuid.uuid4(), description="Pull DNS logs", status=InvestigationActionStatus.COMPLETED,
        created_by_user_id=uuid.uuid4(), completed_by_user_id=uuid.uuid4(), completed_at=datetime.now(timezone.utc), created_at=datetime.now(timezone.utc),
    )
    monkeypatch.setattr(router_module.investigation_session_service, "update_action_status", AsyncMock(return_value=updated))
    headers = make_auth_headers(role=UserRole.ANALYST)

    response = client.patch(
        f"/api/v1/incidents/{uuid.uuid4()}/investigation/sessions/{uuid.uuid4()}/actions/{action_id}",
        json={"status": "completed"}, headers=headers,
    )

    assert response.status_code == 200
    assert response.json()["status"] == "completed"
    assert response.json()["completed_at"] is not None


# ── notes ──────────────────────────────────────────────────────────

def test_add_note_requires_analyst_role(client, db_session, make_auth_headers):
    headers = make_auth_headers(role=UserRole.VIEWER)
    response = client.post(f"/api/v1/incidents/{uuid.uuid4()}/investigation/sessions/{uuid.uuid4()}/notes", json={"body": "x"}, headers=headers)
    assert response.status_code == 403


def test_add_note_returns_the_created_note(client, db_session, make_auth_headers, monkeypatch):
    note = InvestigationNote(id=uuid.uuid4(), session_id=uuid.uuid4(), author_user_id=uuid.uuid4(), body="Called the user.", created_at=datetime.now(timezone.utc))
    monkeypatch.setattr(router_module.investigation_session_service, "create_note", AsyncMock(return_value=note))
    headers = make_auth_headers(role=UserRole.ANALYST)

    response = client.post(f"/api/v1/incidents/{uuid.uuid4()}/investigation/sessions/{uuid.uuid4()}/notes", json={"body": "Called the user."}, headers=headers)

    assert response.status_code == 201
    assert response.json()["body"] == "Called the user."
