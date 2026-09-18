"""
SafeSOC — Endpoints Router Tests
"""

import uuid
from datetime import datetime, timezone

import pytest

from app.core.enums import RiskLevel, SoftwareCategory
from app.db.postgresql import get_db
from app.main import app
from app.models.endpoint import Endpoint
from app.models.endpoint_software import EndpointSoftware


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)


class _FakeSession:
    def __init__(self, existing_endpoints=None):
        self.existing_endpoints: list[Endpoint] = list(existing_endpoints or [])

    async def execute(self, stmt):
        return _FakeResult(self.existing_endpoints)


@pytest.fixture
def db_session():
    fake_session = _FakeSession()

    async def override_get_db():
        yield fake_session

    app.dependency_overrides[get_db] = override_get_db
    yield fake_session
    app.dependency_overrides.pop(get_db, None)


def test_list_endpoints_requires_authentication(client, db_session):
    response = client.get("/api/v1/endpoints")

    assert response.status_code == 401


def test_list_endpoints_returns_the_tenants_endpoints(client, db_session, make_auth_headers):
    tenant_id = uuid.uuid4()
    db_session.existing_endpoints = [
        Endpoint(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            host_id="DESKTOP-042",
            risk_score=65,
            risk_level=RiskLevel.HIGH,
            updated_at=datetime.now(timezone.utc),
        ),
    ]
    headers = make_auth_headers(tenant_id=tenant_id)

    response = client.get("/api/v1/endpoints", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["host_id"] == "DESKTOP-042"
    assert body[0]["risk_score"] == 65
    assert body[0]["risk_level"] == "high"
    assert body[0]["tenant_id"] == str(tenant_id)


def test_list_endpoints_returns_an_empty_list_when_none_exist(client, db_session, make_auth_headers):
    headers = make_auth_headers()

    response = client.get("/api/v1/endpoints", headers=headers)

    assert response.status_code == 200
    assert response.json() == []


# ── GET /api/v1/endpoints/{host_id}/software ──────────────────────────

def test_list_software_requires_authentication(client, db_session):
    response = client.get("/api/v1/endpoints/DESKTOP-042/software")

    assert response.status_code == 401


def test_list_software_returns_the_hosts_inventory(client, db_session, make_auth_headers):
    tenant_id = uuid.uuid4()
    db_session.existing_endpoints = [
        EndpointSoftware(
            id=uuid.uuid4(), tenant_id=tenant_id, host_id="DESKTOP-042", name="Windows 11", version="23H2",
            category=SoftwareCategory.OPERATING_SYSTEM,
            vulnerabilities=[{"id": "DEMO-VULN-0001", "severity": "medium", "title": "Demo issue", "is_synthetic": True}],
            updated_at=datetime.now(timezone.utc),
        ),
    ]
    headers = make_auth_headers(tenant_id=tenant_id)

    response = client.get("/api/v1/endpoints/DESKTOP-042/software", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["name"] == "Windows 11"
    assert body[0]["category"] == "operating_system"
    assert body[0]["vulnerabilities"][0]["id"] == "DEMO-VULN-0001"


def test_list_software_returns_an_empty_list_when_none_recorded(client, db_session, make_auth_headers):
    headers = make_auth_headers()

    response = client.get("/api/v1/endpoints/DESKTOP-999/software", headers=headers)

    assert response.status_code == 200
    assert response.json() == []


# ── POST /{host_id}/report ───────────────────────────────────────

def test_generate_report_requires_authentication(client, db_session):
    response = client.post("/api/v1/endpoints/DESKTOP-042/report")
    assert response.status_code == 401


def test_generate_report_returns_the_saved_report_metadata(client, db_session, make_auth_headers, monkeypatch, tmp_path):
    from datetime import datetime, timezone
    from unittest.mock import AsyncMock

    from app.routers.v1 import endpoints as endpoints_router

    generated_at = datetime(2026, 8, 26, 17, 0, 0, tzinfo=timezone.utc)
    report_path = tmp_path / "investigation-endpoint-DESKTOP-042-20260826T170000Z.pdf"
    report_path.write_bytes(b"%PDF-1.7 fake")
    mock_generate = AsyncMock(return_value=(report_path, generated_at))
    monkeypatch.setattr(endpoints_router, "generate_endpoint_report", mock_generate)

    headers = make_auth_headers()
    response = client.post("/api/v1/endpoints/DESKTOP-042/report", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["filename"] == report_path.name
    assert body["size_bytes"] == report_path.stat().st_size
    assert body["download_url"] == f"/api/v1/reports/{report_path.name}"
    mock_generate.assert_called_once()
    # session_qa defaults to None when the caller sends no request body
    _, kwargs = mock_generate.call_args
    assert kwargs.get("session_qa") is None


def test_generate_report_passes_through_session_qa_when_provided(client, db_session, make_auth_headers, monkeypatch, tmp_path):
    from datetime import datetime, timezone
    from unittest.mock import AsyncMock

    from app.routers.v1 import endpoints as endpoints_router

    generated_at = datetime(2026, 8, 26, 17, 0, 0, tzinfo=timezone.utc)
    report_path = tmp_path / "investigation-endpoint-DESKTOP-042-20260826T170000Z.pdf"
    report_path.write_bytes(b"%PDF-1.7 fake")
    mock_generate = AsyncMock(return_value=(report_path, generated_at))
    monkeypatch.setattr(endpoints_router, "generate_endpoint_report", mock_generate)

    headers = make_auth_headers()
    payload = {"session_qa": [{"question": "Is this host compromised?", "answer": "Evidence insufficient to determine this.", "is_fallback": False}]}
    response = client.post("/api/v1/endpoints/DESKTOP-042/report", json=payload, headers=headers)

    assert response.status_code == 200
    _, kwargs = mock_generate.call_args
    assert kwargs["session_qa"] is not None
    assert kwargs["session_qa"][0].question == "Is this host compromised?"
