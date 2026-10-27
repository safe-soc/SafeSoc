"""
SafeSOC — Threat Intel Refresh Endpoint Tests
POST /api/v1/incidents/{id}/evidence/ips/{ip}/refresh: validation,
tenant scoping via the incident's evidence, Redis cooldown, and that the
lookup itself is only ever enqueued to the worker (never run inline).
"""

import uuid
from unittest.mock import Mock

import pytest

from app.core.enums import UserRole
from app.core.exceptions import IncidentNotFoundError
from app.db.postgresql import get_db
from app.main import app
from app.services import threat_intel_refresh
from app.services.incident_evidence import IncidentEvidence, IPEntity

PUBLIC_IP = "140.246.61.93"


class _FakeSession:
    """Only record_event (audit) touches the session here."""

    def __init__(self):
        self.added = []

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        pass

    async def refresh(self, obj):
        pass


class _FakeRedis:
    """SET NX EX semantics, without expiry — enough to model "within the cooldown"."""

    def __init__(self):
        self.keys: dict[str, str] = {}
        self.calls: list[tuple] = []

    async def set(self, key, value, nx=False, ex=None):
        self.calls.append((key, nx, ex))
        if nx and key in self.keys:
            return None
        self.keys[key] = value
        return True


@pytest.fixture
def db_session():
    session = _FakeSession()

    async def override_get_db():
        yield session

    app.dependency_overrides[get_db] = override_get_db
    yield session
    app.dependency_overrides.pop(get_db, None)


@pytest.fixture
def fake_redis(monkeypatch):
    redis = _FakeRedis()
    monkeypatch.setattr(threat_intel_refresh, "get_client", lambda: redis)
    return redis


@pytest.fixture
def delay_mock(monkeypatch):
    mock = Mock()
    monkeypatch.setattr(threat_intel_refresh.refresh_indicator, "delay", mock)
    return mock


@pytest.fixture
def incident_evidence(monkeypatch):
    """One tenant's incident whose evidence holds PUBLIC_IP; any other tenant/incident is a 404."""
    tenant_id = uuid.uuid4()
    incident_id = uuid.uuid4()

    async def _get_incident_evidence(db, caller_tenant_id, caller_incident_id):
        if caller_tenant_id != tenant_id or caller_incident_id != incident_id:
            raise IncidentNotFoundError(caller_incident_id)
        return IncidentEvidence(
            incident_id=incident_id, hosts=[], users=[], cloud_resources=[],
            ips=[IPEntity(ip=PUBLIC_IP, roles=["source"], alert_count=1, is_public=True)],
        )

    monkeypatch.setattr(threat_intel_refresh, "get_incident_evidence", _get_incident_evidence)
    return tenant_id, incident_id


def _url(incident_id, ip=PUBLIC_IP) -> str:
    return f"/api/v1/incidents/{incident_id}/evidence/ips/{ip}/refresh"


def test_refresh_returns_202_and_enqueues_the_worker_task(client, db_session, fake_redis, delay_mock, incident_evidence, make_auth_headers):
    tenant_id, incident_id = incident_evidence

    response = client.post(_url(incident_id), headers=make_auth_headers(tenant_id=tenant_id))

    assert response.status_code == 202
    assert response.json() == {"queued": True, "ip": PUBLIC_IP}
    delay_mock.assert_called_once_with(PUBLIC_IP)
    assert fake_redis.calls == [(f"ti_refresh:{PUBLIC_IP}", True, 60)]
    assert [entry.action for entry in db_session.added] == ["threat_intel.refresh_requested"]


@pytest.mark.parametrize("ip", ["10.0.0.1", "203.0.113.5", "not-an-ip"])
def test_refresh_rejects_private_reserved_or_invalid_ip_with_400(client, db_session, fake_redis, delay_mock, incident_evidence, make_auth_headers, ip):
    tenant_id, incident_id = incident_evidence

    response = client.post(_url(incident_id, ip), headers=make_auth_headers(tenant_id=tenant_id))

    assert response.status_code == 400
    delay_mock.assert_not_called()


def test_refresh_404s_for_an_ip_not_in_the_incident(client, db_session, fake_redis, delay_mock, incident_evidence, make_auth_headers):
    tenant_id, incident_id = incident_evidence

    response = client.post(_url(incident_id, "8.8.8.8"), headers=make_auth_headers(tenant_id=tenant_id))

    assert response.status_code == 404
    delay_mock.assert_not_called()
    assert fake_redis.calls == []  # cooldown not consumed by a rejected request


def test_refresh_404s_for_another_tenants_incident(client, db_session, fake_redis, delay_mock, incident_evidence, make_auth_headers):
    _, incident_id = incident_evidence

    response = client.post(_url(incident_id), headers=make_auth_headers(tenant_id=uuid.uuid4()))

    assert response.status_code == 404
    delay_mock.assert_not_called()


def test_second_refresh_within_cooldown_is_429(client, db_session, fake_redis, delay_mock, incident_evidence, make_auth_headers):
    tenant_id, incident_id = incident_evidence
    headers = make_auth_headers(tenant_id=tenant_id)

    first = client.post(_url(incident_id), headers=headers)
    second = client.post(_url(incident_id), headers=headers)

    assert first.status_code == 202
    assert second.status_code == 429
    assert second.json()["error"] == "Refreshed recently — try again in a minute."
    delay_mock.assert_called_once()


def test_viewer_cannot_refresh(client, db_session, fake_redis, delay_mock, incident_evidence, make_auth_headers):
    tenant_id, incident_id = incident_evidence

    response = client.post(_url(incident_id), headers=make_auth_headers(tenant_id=tenant_id, role=UserRole.VIEWER))

    assert response.status_code == 403
    delay_mock.assert_not_called()


def test_refresh_indicator_task_is_registered_with_celery():
    from app.tasks.celery_app import celery_app

    assert "app.tasks.enrichment.refresh_indicator" in celery_app.tasks
