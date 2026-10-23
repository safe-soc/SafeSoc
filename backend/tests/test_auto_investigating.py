"""
SafeSOC — Auto-move to INVESTIGATING Tests
An analyst working on an OPEN incident (note, tag, link, assign, or any
investigation-session mutation) moves it to INVESTIGATING, recorded as
a transition by that analyst. Nothing else does: other statuses are
never touched, read-only endpoints and narrative/report generation
don't count, and SOAR automation — which calls the same service
functions with its system actor — must never trigger it.

Incident routes run for real against test_incidents_router's fake DB
session; session routes mock investigation_session's service functions
(as test_investigation_sessions_router does) but run the real hook.
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from app.core.enums import FindingCategory, FindingOrigin, IncidentStatus, InvestigationActionStatus, UserRole
from app.core.exceptions import InvalidStateTransitionError
from app.db.postgresql import get_db
from app.main import app
from app.models.incident import IncidentStateTransition
from app.models.investigation_session import (
    InvestigationAction,
    InvestigationFinding,
    InvestigationNote,
    InvestigationSession,
    InvestigationTurn,
)
from app.models.user import User
from app.routers.v1 import investigation_sessions as sessions_router
from app.services import incidents as incidents_service
from app.services import soar_execution
from tests.test_incidents_router import _FakeSession as _IncidentFakeSession
from tests.test_incidents_router import _seeded_incident


class _FakeSession(_IncidentFakeSession):
    """Also keeps the IncidentStateTransition rows the base fake discards on commit."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.transitions: list[IncidentStateTransition] = []

    def add(self, obj):
        if isinstance(obj, IncidentStateTransition):
            self.transitions.append(obj)
        super().add(obj)


@pytest.fixture
def db_session():
    fake_session = _FakeSession()

    async def override_get_db():
        yield fake_session

    app.dependency_overrides[get_db] = override_get_db
    yield fake_session
    app.dependency_overrides.pop(get_db, None)


@pytest.fixture(autouse=True)
def _no_real_audit_writes(monkeypatch):
    monkeypatch.setattr(incidents_service, "record_event", AsyncMock())


def _now():
    return datetime.now(timezone.utc)


# ── Route table ──────────────────────────────────────────────────────

def _mock_session_services(monkeypatch, incident_id):
    session_id = uuid.uuid4()
    session = InvestigationSession(id=session_id, incident_id=incident_id, created_by_user_id=uuid.uuid4(), created_at=_now())
    turn = InvestigationTurn(
        id=uuid.uuid4(), session_id=session_id, asked_by_user_id=uuid.uuid4(), question="q", answer="a",
        is_fallback=False, created_at=_now(),
    )
    finding = InvestigationFinding(
        id=uuid.uuid4(), session_id=session_id, text="Host confirmed", category=FindingCategory.HYPOTHESIS,
        origin=FindingOrigin.ANALYST, created_by_user_id=uuid.uuid4(), created_at=_now(), updated_at=_now(),
    )
    action = InvestigationAction(
        id=uuid.uuid4(), session_id=session_id, description="Pull logs", status=InvestigationActionStatus.OPEN,
        created_by_user_id=uuid.uuid4(), created_at=_now(),
    )
    note = InvestigationNote(id=uuid.uuid4(), session_id=session_id, author_user_id=uuid.uuid4(), body="n", created_at=_now())
    service = sessions_router.investigation_session_service
    for name, value in [
        ("create_session", session), ("ask_question", turn), ("create_finding", finding),
        ("update_finding_category", finding), ("create_action", action), ("update_action_status", action),
        ("create_note", note),
    ]:
        monkeypatch.setattr(service, name, AsyncMock(return_value=value))
    return session_id


def _route_request(route, incident, db_session, monkeypatch):
    """(method, url, json) for one analyst-action route, with whatever setup it needs."""
    base = f"/api/v1/incidents/{incident.id}"
    if route == "assign":
        assignee = User(id=uuid.uuid4(), tenant_id=incident.tenant_id, email="a@acme.example", password_hash="x", role=UserRole.ANALYST)
        db_session.existing_users = [assignee]
        return "post", f"{base}/assign", {"assignee_user_id": str(assignee.id)}
    if route == "case_note":
        return "post", f"{base}/notes", {"body": "Looking into it."}
    if route == "tags":
        return "post", f"{base}/tags", {"tags": ["phishing"]}
    if route == "link_alert":
        return "post", f"{base}/alerts", {"alert_id": "alert-9"}
    if route == "link_alerts_batch":
        return "post", f"{base}/alerts", {"alert_ids": ["alert-9", "alert-10"]}

    session_id = _mock_session_services(monkeypatch, incident.id)
    session_base = f"{base}/investigation/sessions"
    return {
        "start_session": ("post", session_base, None),
        "ask_question": ("post", f"{session_base}/{session_id}/ask", {"question": "What happened?"}),
        "create_finding": ("post", f"{session_base}/{session_id}/findings", {"text": "x", "category": "hypothesis"}),
        "update_finding": ("patch", f"{session_base}/{session_id}/findings/{uuid.uuid4()}", {"category": "confirmed"}),
        "create_action": ("post", f"{session_base}/{session_id}/actions", {"description": "Pull DNS logs"}),
        "update_action": ("patch", f"{session_base}/{session_id}/actions/{uuid.uuid4()}", {"status": "completed"}),
        "session_note": ("post", f"{session_base}/{session_id}/notes", {"body": "scratch"}),
    }[route]


ANALYST_ROUTES = [
    "assign", "case_note", "tags", "link_alert", "link_alerts_batch",
    "start_session", "ask_question", "create_finding", "update_finding", "create_action", "update_action",
    "session_note",
]


@pytest.mark.parametrize("route", ANALYST_ROUTES)
def test_analyst_action_moves_an_open_incident_to_investigating(route, client, db_session, make_auth_headers, monkeypatch):
    tenant_id, user_id = uuid.uuid4(), uuid.uuid4()
    incident = _seeded_incident(tenant_id=tenant_id, status=IncidentStatus.OPEN)
    db_session.existing_incidents = [incident]
    method, url, body = _route_request(route, incident, db_session, monkeypatch)
    headers = make_auth_headers(tenant_id=tenant_id, user_id=user_id, role=UserRole.ANALYST)

    response = getattr(client, method)(url, json=body, headers=headers)

    assert response.status_code in (200, 201), response.text
    assert incident.status == IncidentStatus.INVESTIGATING
    assert len(db_session.transitions) == 1
    transition = db_session.transitions[0]
    assert (transition.from_status, transition.to_status) == (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING)
    assert transition.changed_by_user_id == user_id


@pytest.mark.parametrize("route", ["assign", "tags", "link_alert", "link_alerts_batch"])
def test_incident_returning_routes_respond_with_the_new_status(route, client, db_session, make_auth_headers, monkeypatch):
    tenant_id = uuid.uuid4()
    incident = _seeded_incident(tenant_id=tenant_id, status=IncidentStatus.OPEN)
    db_session.existing_incidents = [incident]
    method, url, body = _route_request(route, incident, db_session, monkeypatch)

    response = getattr(client, method)(url, json=body, headers=make_auth_headers(tenant_id=tenant_id))

    assert response.json()["status"] == "investigating"


@pytest.mark.parametrize("status", [IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE])
@pytest.mark.parametrize("route", ANALYST_ROUTES)
def test_analyst_action_leaves_any_other_status_unchanged(route, status, client, db_session, make_auth_headers, monkeypatch):
    tenant_id = uuid.uuid4()
    incident = _seeded_incident(tenant_id=tenant_id, status=status)
    db_session.existing_incidents = [incident]
    method, url, body = _route_request(route, incident, db_session, monkeypatch)

    response = getattr(client, method)(url, json=body, headers=make_auth_headers(tenant_id=tenant_id))

    assert response.status_code in (200, 201), response.text
    assert incident.status == status
    assert db_session.transitions == []


def test_a_viewer_who_cannot_act_cannot_trigger_the_transition(client, db_session, make_auth_headers):
    tenant_id = uuid.uuid4()
    incident = _seeded_incident(tenant_id=tenant_id, status=IncidentStatus.OPEN)
    db_session.existing_incidents = [incident]

    response = client.post(
        f"/api/v1/incidents/{incident.id}/notes", json={"body": "x"},
        headers=make_auth_headers(tenant_id=tenant_id, role=UserRole.VIEWER),
    )

    assert response.status_code == 403
    assert incident.status == IncidentStatus.OPEN


# ── What must NOT transition ─────────────────────────────────────────

def test_reading_and_narrative_and_report_leave_an_open_incident_open(client, db_session, make_auth_headers, monkeypatch, tmp_path):
    from unittest.mock import Mock

    from app.clients import ollama
    from app.routers.v1 import incidents as incidents_router

    tenant_id = uuid.uuid4()
    incident = _seeded_incident(tenant_id=tenant_id, status=IncidentStatus.OPEN)
    db_session.existing_incidents = [incident]
    # Same stubs test_incidents_router uses for the narrative path: the
    # timeline reads OpenSearch and the audit log, neither in the fake DB.
    monkeypatch.setattr("app.services.incident_timeline.get_alerts_by_ids", AsyncMock(return_value=[]))
    monkeypatch.setattr("app.services.incident_timeline.list_events", AsyncMock(return_value=([], 0)))
    monkeypatch.setattr("app.services.incident_evidence.get_alerts_by_ids", AsyncMock(return_value=[]))
    monkeypatch.setattr("app.services.incident_narrative.record_event", AsyncMock())
    monkeypatch.setattr(ollama, "generate", Mock(return_value="Summary."))
    report_path = tmp_path / "investigation-incident-test.pdf"
    report_path.write_bytes(b"%PDF-1.7 fake")
    monkeypatch.setattr(incidents_router, "generate_incident_report", AsyncMock(return_value=(report_path, _now())))
    headers = make_auth_headers(tenant_id=tenant_id, role=UserRole.ANALYST)
    base = f"/api/v1/incidents/{incident.id}"

    assert client.get(base, headers=headers).status_code == 200
    assert client.get(f"{base}/notes", headers=headers).status_code == 200
    assert client.post(f"{base}/narrative", headers=headers).status_code == 200
    assert client.post(f"{base}/report", headers=headers).status_code == 200

    assert incident.status == IncidentStatus.OPEN
    assert db_session.transitions == []


@pytest.mark.asyncio
async def test_soar_add_incident_note_leaves_an_open_incident_open(monkeypatch):
    tenant_id = uuid.uuid4()
    incident = _seeded_incident(tenant_id=tenant_id, status=IncidentStatus.OPEN)
    session = _FakeSession(existing_incidents=[incident])
    monkeypatch.setattr(soar_execution, "_get_or_create_system_actor", AsyncMock(return_value=uuid.uuid4()))

    result = await soar_execution._execute_add_incident_note(session, tenant_id, incident.id, {"note": "Auto-triaged."})

    assert result["success"] is True
    assert len(session.existing_notes) == 1  # the real add_note ran
    assert incident.status == IncidentStatus.OPEN
    assert session.transitions == []


@pytest.mark.asyncio
async def test_soar_create_investigation_action_leaves_an_open_incident_open(monkeypatch):
    tenant_id = uuid.uuid4()
    incident = _seeded_incident(tenant_id=tenant_id, status=IncidentStatus.OPEN)
    session = _FakeSession(existing_incidents=[incident])
    soar_session = InvestigationSession(id=uuid.uuid4(), incident_id=incident.id, created_by_user_id=uuid.uuid4(), created_at=_now())
    action = InvestigationAction(
        id=uuid.uuid4(), session_id=soar_session.id, description="Collect logs", status=InvestigationActionStatus.OPEN,
        created_by_user_id=uuid.uuid4(), created_at=_now(),
    )
    monkeypatch.setattr(soar_execution, "_get_or_create_system_actor", AsyncMock(return_value=uuid.uuid4()))
    monkeypatch.setattr(soar_execution, "_get_or_create_soar_session", AsyncMock(return_value=soar_session))
    monkeypatch.setattr(soar_execution.investigation_session_service, "create_action", AsyncMock(return_value=action))
    transition_spy = AsyncMock()
    monkeypatch.setattr(incidents_service, "transition_incident", transition_spy)

    result = await soar_execution._execute_create_investigation_action(
        session, tenant_id, incident.id, {"description": "Collect logs"}
    )

    assert result["success"] is True
    transition_spy.assert_not_called()
    assert incident.status == IncidentStatus.OPEN


# ── The helper itself ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_helper_returns_true_and_transitions_an_open_incident():
    tenant_id, actor = uuid.uuid4(), uuid.uuid4()
    incident = _seeded_incident(tenant_id=tenant_id, status=IncidentStatus.OPEN)
    session = _FakeSession(existing_incidents=[incident])

    moved = await incidents_service.mark_investigating_on_analyst_action(session, tenant_id, incident.id, actor)

    assert moved is True
    assert incident.status == IncidentStatus.INVESTIGATING


@pytest.mark.asyncio
async def test_helper_returns_false_without_raising_when_already_investigating():
    tenant_id = uuid.uuid4()
    incident = _seeded_incident(tenant_id=tenant_id, status=IncidentStatus.INVESTIGATING)
    session = _FakeSession(existing_incidents=[incident])

    moved = await incidents_service.mark_investigating_on_analyst_action(session, tenant_id, incident.id, uuid.uuid4())

    assert moved is False
    assert session.transitions == []


@pytest.mark.asyncio
async def test_helper_swallows_a_concurrent_transition(monkeypatch):
    """Read as OPEN, but another request moved it first: transition_incident raises, the helper reports False."""
    tenant_id = uuid.uuid4()
    incident = _seeded_incident(tenant_id=tenant_id, status=IncidentStatus.OPEN)
    session = _FakeSession(existing_incidents=[incident])
    monkeypatch.setattr(
        incidents_service, "transition_incident",
        AsyncMock(side_effect=InvalidStateTransitionError(IncidentStatus.INVESTIGATING, IncidentStatus.INVESTIGATING)),
    )

    moved = await incidents_service.mark_investigating_on_analyst_action(session, tenant_id, incident.id, uuid.uuid4())

    assert moved is False
