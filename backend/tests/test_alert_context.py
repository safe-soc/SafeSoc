"""
SafeSOC — Alert Context Endpoint Tests
GET /api/v1/alerts/{alert_id}/context: full alert + triage state, the
tenant incident containing it, and cached TI for its IPs — with the
tenant boundary enforced here because get_alert_by_id isn't tenant-filtered.
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
from sqlalchemy.dialects import postgresql

from app.core.enums import DismissReason, IncidentStatus, TIProvider, UserRole
from app.db.postgresql import get_db
from app.main import app
from app.models.alert_annotation import AlertAnnotation
from app.models.incident import Incident
from app.models.ti_cache import TICache
from app.services import alert_context
from app.services.incident_summary import IncidentSummary

PUBLIC_IP = "140.246.61.93"
PRIVATE_IP = "10.0.0.5"


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)


class _FakeSession:
    """Routes AlertAnnotation / Incident / TICache selects to their own lists; records the statements."""

    def __init__(self, annotations=None, incidents=None, ti_cache=None):
        self.annotations = list(annotations or [])
        self.incidents = list(incidents or [])
        self.ti_cache = list(ti_cache or [])
        self.statements = []

    async def execute(self, stmt, params=None):
        self.statements.append(stmt)
        target = stmt.column_descriptions[0].get("type")
        if target is AlertAnnotation:
            return _FakeResult(self.annotations)
        if target is Incident:
            return _FakeResult(self.incidents)
        if target is TICache:
            return _FakeResult(self.ti_cache)
        return _FakeResult([])


def _install(session):
    async def override_get_db():
        yield session

    app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(autouse=True)
def _cleanup_db_override():
    yield
    app.dependency_overrides.pop(get_db, None)


@pytest.fixture(autouse=True)
def _mock_summary(monkeypatch):
    async def _summarize(incidents):
        return {incident.id: IncidentSummary(hosts=["WEB-01"]) for incident in incidents}

    monkeypatch.setattr(alert_context, "summarize_incidents", _summarize)


def _alert(tenant_id, **overrides) -> dict:
    doc = {
        "alert_id": "a-1", "tenant_id": str(tenant_id), "source": "synthetic", "log_type": "network",
        "timestamp": "2026-10-27T10:00:00Z", "host_id": "WEB-01", "host_ip": "10.0.0.2", "user": "alice",
        "action": "outbound_connection", "description": "x", "severity": "high", "raw_log": "{}",
        "source_ip": PUBLIC_IP, "destination_ip": PRIVATE_IP,
    }
    doc.update(overrides)
    return doc


def _mock_alert(monkeypatch, doc):
    monkeypatch.setattr(alert_context, "get_alert_by_id", AsyncMock(return_value=doc))


def _incident(tenant_id, alert_ids, updated_at=None) -> Incident:
    now = updated_at or datetime.now(timezone.utc)
    return Incident(
        id=uuid.uuid4(), tenant_id=tenant_id, status=IncidentStatus.INVESTIGATING, alert_ids=alert_ids,
        category=None, tags=[], created_at=now, updated_at=now,
    )


def test_context_returns_alert_with_triage_state(client, monkeypatch, make_auth_headers):
    tenant_id = uuid.uuid4()
    _mock_alert(monkeypatch, _alert(tenant_id))
    annotation = AlertAnnotation(
        id=uuid.uuid4(), tenant_id=tenant_id, alert_id="a-1", acknowledged=False, dismissed=True,
        dismiss_reason=DismissReason.OTHER, dismiss_note="lab traffic", updated_by_user_id=uuid.uuid4(),
    )
    _install(_FakeSession(annotations=[annotation]))

    response = client.get("/api/v1/alerts/a-1/context", headers=make_auth_headers(tenant_id=tenant_id, role=UserRole.VIEWER))

    assert response.status_code == 200
    alert = response.json()["alert"]
    assert alert["alert_id"] == "a-1" and alert["raw_log"] == "{}"
    assert alert["dismissed"] is True and alert["acknowledged"] is False
    assert alert["dismiss_reason"] == "other" and alert["dismiss_note"] == "lab traffic"


def test_context_404s_for_an_unknown_alert(client, monkeypatch, make_auth_headers):
    _mock_alert(monkeypatch, None)
    _install(_FakeSession())

    response = client.get("/api/v1/alerts/missing/context", headers=make_auth_headers())

    assert response.status_code == 404


def test_context_404s_for_another_tenants_alert(client, monkeypatch, make_auth_headers):
    _mock_alert(monkeypatch, _alert(uuid.uuid4()))
    session = _FakeSession()
    _install(session)

    response = client.get("/api/v1/alerts/a-1/context", headers=make_auth_headers(tenant_id=uuid.uuid4()))

    assert response.status_code == 404
    assert session.statements == []  # nothing about the alert was looked up for the wrong tenant


def test_context_includes_the_incident_containing_the_alert(client, monkeypatch, make_auth_headers):
    tenant_id = uuid.uuid4()
    _mock_alert(monkeypatch, _alert(tenant_id))
    newer = _incident(tenant_id, ["a-0", "a-1"], datetime(2026, 10, 27, tzinfo=timezone.utc))
    older = _incident(tenant_id, ["a-1"], datetime(2026, 10, 1, tzinfo=timezone.utc))
    session = _FakeSession(incidents=[newer, older])  # the query orders by updated_at desc
    _install(session)

    response = client.get("/api/v1/alerts/a-1/context", headers=make_auth_headers(tenant_id=tenant_id))

    incident = response.json()["incident"]
    assert incident["id"] == str(newer.id)
    assert incident["hosts"] == ["WEB-01"] and incident["status"] == "investigating"
    incident_sql = str(
        next(s for s in session.statements if s.column_descriptions[0].get("type") is Incident)
        .compile(dialect=postgresql.dialect())
    )
    assert "CAST(incidents.alert_ids AS JSONB) @>" in incident_sql
    assert "incidents.tenant_id" in incident_sql


def test_context_incident_is_null_when_alert_is_in_no_incident(client, monkeypatch, make_auth_headers):
    tenant_id = uuid.uuid4()
    _mock_alert(monkeypatch, _alert(tenant_id))
    # A row whose alert_ids don't actually contain the alert is never attached.
    _install(_FakeSession(incidents=[_incident(tenant_id, ["a-9"])]))

    response = client.get("/api/v1/alerts/a-1/context", headers=make_auth_headers(tenant_id=tenant_id))

    assert response.json()["incident"] is None


def test_context_ip_intel_for_a_cached_public_ip(client, monkeypatch, make_auth_headers):
    tenant_id = uuid.uuid4()
    _mock_alert(monkeypatch, _alert(tenant_id))
    row = TICache(
        id=uuid.uuid4(), indicator=PUBLIC_IP, provider=TIProvider.ABUSEIPDB,
        result={"abuse": {"confidence": 90, "isp": "Example ISP"}}, is_malicious=True,
        expires_at=None, created_at=datetime(2026, 10, 26, tzinfo=timezone.utc),
    )
    _install(_FakeSession(ti_cache=[row]))

    response = client.get("/api/v1/alerts/a-1/context", headers=make_auth_headers(tenant_id=tenant_id))

    ip_intel = response.json()["ip_intel"]
    assert set(ip_intel) == {PUBLIC_IP, PRIVATE_IP}
    assert ip_intel[PUBLIC_IP]["is_public"] is True
    assert ip_intel[PUBLIC_IP]["ti"]["is_malicious"] is True
    assert ip_intel[PUBLIC_IP]["ti"]["abuse"]["isp"] == "Example ISP"
    assert ip_intel[PUBLIC_IP]["ti"]["abuse_status"] == "ok" and ip_intel[PUBLIC_IP]["ti"]["vt_status"] == "missing"
    assert ip_intel[PRIVATE_IP] == {"ti": None, "is_public": False}


def test_context_ip_intel_is_empty_when_the_alert_has_no_ips(client, monkeypatch, make_auth_headers):
    tenant_id = uuid.uuid4()
    _mock_alert(monkeypatch, _alert(tenant_id, source_ip=None, destination_ip=None))
    _install(_FakeSession())

    response = client.get("/api/v1/alerts/a-1/context", headers=make_auth_headers(tenant_id=tenant_id))

    assert response.json()["ip_intel"] == {}


def test_context_requires_authentication(client, monkeypatch):
    _install(_FakeSession())

    assert client.get("/api/v1/alerts/a-1/context").status_code == 401
