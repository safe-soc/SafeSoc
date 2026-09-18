"""
SafeSOC — Compliance Center Router Tests
HTTP-layer wiring: authentication, tenant-scoping, and that a
requirement id can never be used to reach another tenant's evidence.
Business logic (status classification, evidence aggregation) is
covered directly against services/compliance.py in test_compliance.py
— these tests mock that service, mirroring
test_investigation_sessions_router.py's own precedent.
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from app.core.compliance_mapping import get_requirement
from app.core.enums import ComplianceStatus, IncidentStatus, UserRole
from app.core.exceptions import ComplianceRequirementNotFoundError
from app.db.postgresql import get_db
from app.main import app
from app.models.incident import Incident
from app.routers.v1 import compliance as router_module
from app.services.compliance import InvestigationRef, RequirementAssessment


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


def _assessment(requirement_id: str, *, status=ComplianceStatus.EVIDENCE_AVAILABLE, related_incidents=None, related_investigations=None) -> RequirementAssessment:
    requirement = get_requirement(requirement_id)
    return RequirementAssessment(
        requirement=requirement,
        status=status,
        evidence_summary="Evidence available for this test.",
        evidence_count=3,
        metrics={"incidents": 3},
        recommended_action="No action required.",
        last_evaluated=datetime.now(timezone.utc),
        related_incidents=related_incidents or [],
        related_investigations=related_investigations or [],
    )


def _all_assessments() -> list[RequirementAssessment]:
    from app.core.compliance_mapping import COMPLIANCE_REQUIREMENTS
    return [_assessment(r.id) for r in COMPLIANCE_REQUIREMENTS]


# ── GET /requirements (list) ───────────────────────────────────────────

def test_list_requirements_requires_authentication(client, db_session):
    response = client.get("/api/v1/compliance/requirements")
    assert response.status_code == 401


def test_list_requirements_is_readable_by_a_viewer(client, db_session, make_auth_headers, monkeypatch):
    monkeypatch.setattr(router_module.compliance_service, "get_compliance_posture", AsyncMock(return_value=_all_assessments()))
    headers = make_auth_headers(role=UserRole.VIEWER)

    response = client.get("/api/v1/compliance/requirements", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["requirements_assessed"] == len(_all_assessments())
    assert len(body["frameworks"]) == 3


def test_list_requirements_derives_tenant_from_jwt_not_the_request(client, db_session, make_auth_headers, monkeypatch):
    tenant_id = uuid.uuid4()
    mock = AsyncMock(return_value=_all_assessments())
    monkeypatch.setattr(router_module.compliance_service, "get_compliance_posture", mock)
    headers = make_auth_headers(tenant_id=tenant_id, role=UserRole.VIEWER)

    client.get("/api/v1/compliance/requirements", headers=headers)

    mock.assert_called_once()
    assert mock.call_args.args[1] == tenant_id


def test_list_requirements_response_never_uses_forbidden_compliance_language(client, db_session, make_auth_headers, monkeypatch):
    monkeypatch.setattr(router_module.compliance_service, "get_compliance_posture", AsyncMock(return_value=_all_assessments()))
    headers = make_auth_headers(role=UserRole.VIEWER)

    response = client.get("/api/v1/compliance/requirements", headers=headers)

    body_lower = response.text.lower()
    for phrase in ("non-compliant", "legally compliant", "legally non-compliant"):
        assert phrase not in body_lower


# ── GET /requirements/{id} (detail) ────────────────────────────────────

def test_get_requirement_detail_requires_authentication(client, db_session):
    response = client.get("/api/v1/compliance/requirements/DPDP-R1")
    assert response.status_code == 401


def test_get_requirement_detail_is_readable_by_a_viewer(client, db_session, make_auth_headers, monkeypatch):
    monkeypatch.setattr(router_module.compliance_service, "get_requirement_detail", AsyncMock(return_value=_assessment("DPDP-R2")))
    headers = make_auth_headers(role=UserRole.VIEWER)

    response = client.get("/api/v1/compliance/requirements/DPDP-R2", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == "DPDP-R2"
    assert body["status"] == "evidence_available"
    assert "what_safesoc_can_observe" in body
    assert "what_safesoc_cannot_verify" in body


def test_get_requirement_detail_returns_404_for_an_unknown_id(client, db_session, make_auth_headers, monkeypatch):
    monkeypatch.setattr(
        router_module.compliance_service, "get_requirement_detail",
        AsyncMock(side_effect=ComplianceRequirementNotFoundError("NOPE")),
    )
    headers = make_auth_headers(role=UserRole.VIEWER)

    response = client.get("/api/v1/compliance/requirements/NOPE", headers=headers)

    assert response.status_code == 404


def test_get_requirement_detail_derives_tenant_from_jwt_not_the_path(client, db_session, make_auth_headers, monkeypatch):
    tenant_id = uuid.uuid4()
    mock = AsyncMock(return_value=_assessment("CERTIN-R2"))
    monkeypatch.setattr(router_module.compliance_service, "get_requirement_detail", mock)
    headers = make_auth_headers(tenant_id=tenant_id, role=UserRole.VIEWER)

    client.get("/api/v1/compliance/requirements/CERTIN-R2", headers=headers)

    mock.assert_called_once()
    assert mock.call_args.args[1] == tenant_id
    assert mock.call_args.args[2] == "CERTIN-R2"


def test_requirement_id_cannot_be_used_to_read_another_tenants_evidence(client, db_session, make_auth_headers, monkeypatch):
    """
    The requirement id space is the same static list for every tenant
    (core/compliance_mapping.py) — evidence is always computed for
    whichever tenant the JWT authenticates, never a caller-influenced
    value. Simulate two tenants asking for the SAME requirement id and
    confirm each only ever gets evidence computed for their own,
    JWT-derived tenant.
    """
    tenant_a = uuid.uuid4()
    tenant_b = uuid.uuid4()
    seen_tenant_ids: list[uuid.UUID] = []

    async def fake_get_detail(db, tenant_id, requirement_id):
        seen_tenant_ids.append(tenant_id)
        return _assessment(requirement_id)

    monkeypatch.setattr(router_module.compliance_service, "get_requirement_detail", fake_get_detail)

    response_a = client.get("/api/v1/compliance/requirements/DPDP-R2", headers=make_auth_headers(tenant_id=tenant_a, role=UserRole.VIEWER))
    response_b = client.get("/api/v1/compliance/requirements/DPDP-R2", headers=make_auth_headers(tenant_id=tenant_b, role=UserRole.VIEWER))

    assert response_a.status_code == 200
    assert response_b.status_code == 200
    assert seen_tenant_ids == [tenant_a, tenant_b]


def test_related_incidents_and_investigations_are_included_in_detail(client, db_session, make_auth_headers, monkeypatch):
    incident = Incident(
        id=uuid.uuid4(), tenant_id=uuid.uuid4(), status=IncidentStatus.OPEN,
        alert_ids=[], category=None, confidence=None, tags=[], created_at=datetime.now(timezone.utc),
    )
    investigation_ref = InvestigationRef(session_id=uuid.uuid4(), incident_id=incident.id, created_at=datetime.now(timezone.utc))
    assessment = _assessment("DPDP-R2", related_incidents=[incident], related_investigations=[investigation_ref])
    monkeypatch.setattr(router_module.compliance_service, "get_requirement_detail", AsyncMock(return_value=assessment))
    headers = make_auth_headers(role=UserRole.VIEWER)

    response = client.get("/api/v1/compliance/requirements/DPDP-R2", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["related_incidents"][0]["id"] == str(incident.id)
    assert body["related_investigations"][0]["session_id"] == str(investigation_ref.session_id)


# ── No write surface ────────────────────────────────────────────────────

def test_compliance_router_exposes_no_write_methods():
    for route in app.routes:
        if getattr(route, "path", "").startswith("/api/v1/compliance"):
            assert route.methods <= {"GET", "HEAD", "OPTIONS"}
