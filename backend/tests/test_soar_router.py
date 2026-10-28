"""
SafeSOC — SOAR Router Tests (Phase 1: read-only)
HTTP-layer wiring: authentication, that reads are open to any role
(no write endpoints exist to gate), and — the critical property —
that a run_id can never be used to bypass its incident's tenant
authorization. Mocks services/soar.py, mirroring
test_investigation_sessions_router.py's and test_compliance_router.py's
own precedent for testing a router against a mocked service layer.
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from app.core.enums import (
    AutonomyClass,
    CorrelationPattern,
    RecommendationSource,
    SoarActionStatus,
    SoarActionType,
    SoarRunStatus,
    SoarTriggerSource,
    SoarVerificationStatus,
    UserRole,
)
from app.core.exceptions import IncidentNotFoundError, SoarRunNotFoundError
from app.db.postgresql import get_db
from app.main import app
from app.models.soar import SoarActionExecution, SoarPlaybookRun
from app.routers.v1 import soar as router_module


class _FakeSession:
    async def execute(self, *args, **kwargs):
        raise AssertionError("the service layer is mocked in these tests — no query should reach the fake db session")


@pytest.fixture
def db_session():
    fake_session = _FakeSession()

    async def override_get_db():
        yield fake_session

    app.dependency_overrides[get_db] = override_get_db
    yield fake_session
    app.dependency_overrides.pop(get_db, None)


def _run(incident_id=None, run_id=None) -> SoarPlaybookRun:
    return SoarPlaybookRun(
        id=run_id or uuid.uuid4(), incident_id=incident_id or uuid.uuid4(), playbook_id="pb-successful-compromise",
        triggered_by=SoarTriggerSource.MANUAL, status=SoarRunStatus.PENDING, started_at=None, completed_at=None,
        created_at=datetime.now(timezone.utc),
    )


def _action() -> SoarActionExecution:
    return SoarActionExecution(
        id=uuid.uuid4(), playbook_run_id=uuid.uuid4(), action_type=SoarActionType.ADD_INCIDENT_NOTE,
        parameters={"note": "x"}, autonomy_class=AutonomyClass.AUTOMATIC, recommended_by=RecommendationSource.PLAYBOOK_AUTO,
        status=SoarActionStatus.PENDING, approved_by_user_id=None, approved_at=None, executed_at=None, result=None,
        verification_status=SoarVerificationStatus.NOT_VERIFIED, verified_at=None, created_at=datetime.now(timezone.utc),
    )


# ── GET /api/v1/soar/playbooks ──────────────────────────────────────

def test_list_playbooks_requires_authentication(client, db_session):
    response = client.get("/api/v1/soar/playbooks")
    assert response.status_code == 401


def test_list_playbooks_is_readable_by_a_viewer(client, db_session, make_auth_headers):
    headers = make_auth_headers(role=UserRole.VIEWER)
    response = client.get("/api/v1/soar/playbooks", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert len(body) == len(CorrelationPattern)  # one per CorrelationPattern
    assert {p["id"] for p in body} >= {"pb-successful-compromise", "pb-credential-brute-force"}


def test_list_playbooks_never_exposes_a_never_autonomous_action(client, db_session, make_auth_headers):
    headers = make_auth_headers(role=UserRole.VIEWER)
    response = client.get("/api/v1/soar/playbooks", headers=headers)
    action_types = {step["action_type"] for playbook in response.json() for step in playbook["steps"]}
    forbidden = {"delete_evidence", "delete_account", "destructive_filesystem_action", "irreversible_production_change"}
    assert action_types.isdisjoint(forbidden)


# ── GET /api/v1/incidents/{id}/soar/runs ────────────────────────────

def test_list_runs_requires_authentication(client, db_session):
    response = client.get(f"/api/v1/incidents/{uuid.uuid4()}/soar/runs")
    assert response.status_code == 401


def test_list_runs_is_readable_by_a_viewer(client, db_session, make_auth_headers, monkeypatch):
    incident_id = uuid.uuid4()
    runs = [_run(incident_id=incident_id), _run(incident_id=incident_id)]
    monkeypatch.setattr(router_module.soar_service, "list_runs", AsyncMock(return_value=runs))
    headers = make_auth_headers(role=UserRole.VIEWER)

    response = client.get(f"/api/v1/incidents/{incident_id}/soar/runs", headers=headers)

    assert response.status_code == 200
    assert len(response.json()) == 2


def test_list_runs_derives_tenant_from_jwt_not_the_request(client, db_session, make_auth_headers, monkeypatch):
    tenant_id = uuid.uuid4()
    incident_id = uuid.uuid4()
    mock = AsyncMock(return_value=[])
    monkeypatch.setattr(router_module.soar_service, "list_runs", mock)
    headers = make_auth_headers(tenant_id=tenant_id, role=UserRole.VIEWER)

    client.get(f"/api/v1/incidents/{incident_id}/soar/runs", headers=headers)

    mock.assert_called_once()
    assert mock.call_args.args[1] == tenant_id
    assert mock.call_args.args[2] == incident_id


def test_list_runs_returns_404_for_a_cross_tenant_incident(client, db_session, make_auth_headers, monkeypatch):
    monkeypatch.setattr(router_module.soar_service, "list_runs", AsyncMock(side_effect=IncidentNotFoundError(uuid.uuid4())))
    headers = make_auth_headers(role=UserRole.VIEWER)

    response = client.get(f"/api/v1/incidents/{uuid.uuid4()}/soar/runs", headers=headers)

    assert response.status_code == 404


# ── GET /api/v1/incidents/{id}/soar/runs/{run_id} ───────────────────

def test_get_run_detail_requires_authentication(client, db_session):
    response = client.get(f"/api/v1/incidents/{uuid.uuid4()}/soar/runs/{uuid.uuid4()}")
    assert response.status_code == 401


def test_get_run_detail_is_readable_by_a_viewer(client, db_session, make_auth_headers, monkeypatch):
    incident_id = uuid.uuid4()
    run = _run(incident_id=incident_id)
    action = _action()
    monkeypatch.setattr(router_module.soar_service, "get_run", AsyncMock(return_value=(run, [action])))
    headers = make_auth_headers(role=UserRole.VIEWER)

    response = client.get(f"/api/v1/incidents/{incident_id}/soar/runs/{run.id}", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == str(run.id)
    assert body["incident_id"] == str(incident_id)
    assert len(body["actions"]) == 1
    assert body["actions"][0]["action_type"] == "add_incident_note"
    assert body["actions"][0]["autonomy_class"] == "automatic"


def test_get_run_detail_derives_tenant_from_jwt_not_the_path(client, db_session, make_auth_headers, monkeypatch):
    tenant_id = uuid.uuid4()
    incident_id = uuid.uuid4()
    run_id = uuid.uuid4()
    mock = AsyncMock(return_value=(_run(incident_id=incident_id, run_id=run_id), []))
    monkeypatch.setattr(router_module.soar_service, "get_run", mock)
    headers = make_auth_headers(tenant_id=tenant_id, role=UserRole.VIEWER)

    client.get(f"/api/v1/incidents/{incident_id}/soar/runs/{run_id}", headers=headers)

    mock.assert_called_once()
    assert mock.call_args.args[1] == tenant_id
    assert mock.call_args.args[2] == incident_id
    assert mock.call_args.args[3] == run_id


def test_get_run_detail_returns_404_for_a_run_id_that_belongs_to_a_different_incident(client, db_session, make_auth_headers, monkeypatch):
    """
    The critical isolation property this phase must prove: a real
    run_id, requested under an incident_id it does NOT belong to, must
    404 exactly like an unknown id — never resolve just because the
    run_id itself is valid somewhere.
    """
    monkeypatch.setattr(router_module.soar_service, "get_run", AsyncMock(side_effect=SoarRunNotFoundError(uuid.uuid4())))
    headers = make_auth_headers(role=UserRole.VIEWER)

    response = client.get(f"/api/v1/incidents/{uuid.uuid4()}/soar/runs/{uuid.uuid4()}", headers=headers)

    assert response.status_code == 404


def test_get_run_detail_returns_404_for_a_cross_tenant_incident(client, db_session, make_auth_headers, monkeypatch):
    monkeypatch.setattr(router_module.soar_service, "get_run", AsyncMock(side_effect=IncidentNotFoundError(uuid.uuid4())))
    headers = make_auth_headers(role=UserRole.VIEWER)

    response = client.get(f"/api/v1/incidents/{uuid.uuid4()}/soar/runs/{uuid.uuid4()}", headers=headers)

    assert response.status_code == 404


def test_two_tenants_requesting_the_same_run_id_each_only_see_their_own_service_call(client, db_session, make_auth_headers, monkeypatch):
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    incident_id, run_id = uuid.uuid4(), uuid.uuid4()
    seen_tenant_ids: list[uuid.UUID] = []

    async def fake_get_run(db, tenant_id, incident_id_arg, run_id_arg):
        seen_tenant_ids.append(tenant_id)
        return _run(incident_id=incident_id_arg, run_id=run_id_arg), []

    monkeypatch.setattr(router_module.soar_service, "get_run", fake_get_run)

    response_a = client.get(f"/api/v1/incidents/{incident_id}/soar/runs/{run_id}", headers=make_auth_headers(tenant_id=tenant_a, role=UserRole.VIEWER))
    response_b = client.get(f"/api/v1/incidents/{incident_id}/soar/runs/{run_id}", headers=make_auth_headers(tenant_id=tenant_b, role=UserRole.VIEWER))

    assert response_a.status_code == 200
    assert response_b.status_code == 200
    assert seen_tenant_ids == [tenant_a, tenant_b]


# ── Write surface (Phase 3: approve/reject only) ─────────────────────
#
# Phase 1 asserted no write routes existed at all. Phase 3 adds exactly
# two — approve and reject — and nothing else: there is still no HTTP
# "execute" route (execution only ever happens via the Celery worker,
# never a direct API call), matching services/soar_execution.py's own
# docstring on there being no second execution mechanism.
#
# Walked via app.openapi()["paths"] rather than app.routes directly:
# the internal shape of app.routes (flattened APIRoute objects vs.
# opaque included-router wrappers) varies across FastAPI/Starlette
# versions, but the generated OpenAPI schema is the actual,
# version-independent API surface — the same thing a real HTTP client
# (or the frontend) would see.

def _soar_paths() -> dict:
    schema = app.openapi()
    return {path: methods for path, methods in schema["paths"].items() if "/soar" in path}


def test_soar_router_only_exposes_approve_and_reject_as_writes():
    for path, methods in _soar_paths().items():
        extra_methods = {m.upper() for m in methods} - {"GET", "HEAD", "OPTIONS"}
        if extra_methods:
            assert extra_methods == {"POST"}, f"{path} exposes {extra_methods}"
            assert path.endswith("/approve") or path.endswith("/reject"), f"{path} exposes an unexpected write method"


def test_no_execute_route_exists():
    assert not any("execute" in path for path in _soar_paths())


def test_approve_and_reject_routes_exist():
    paths = _soar_paths()
    assert any(path.endswith("/actions/{action_id}/approve") for path in paths)
    assert any(path.endswith("/actions/{action_id}/reject") for path in paths)
