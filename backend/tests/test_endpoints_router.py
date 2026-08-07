"""
SafeSOC — Endpoints Router Tests
"""

import uuid
from datetime import datetime, timezone

import pytest

from app.core.enums import RiskLevel
from app.db.postgresql import get_db
from app.main import app
from app.models.endpoint import Endpoint


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
