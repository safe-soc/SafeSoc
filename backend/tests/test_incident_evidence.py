"""
SafeSOC — Incident Evidence Extraction Service Tests (SS-100)
"""

import uuid
from unittest.mock import AsyncMock

import pytest

from app.core.enums import IncidentStatus, RiskLevel, TIProvider
from app.core.exceptions import IncidentNotFoundError
from app.models.endpoint import Endpoint
from app.models.incident import Incident
from app.models.ti_cache import TICache
from app.services.incident_evidence import get_incident_evidence


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)


class _FakeSession:
    """Fake AsyncSession routing Endpoint/TICache selects, mirroring tests/test_incidents.py's own fake."""

    def __init__(self, existing_endpoints=None, existing_ti_cache=None):
        self.existing_endpoints: list[Endpoint] = list(existing_endpoints or [])
        self.existing_ti_cache: list[TICache] = list(existing_ti_cache or [])

    async def execute(self, stmt, params=None):
        target = getattr(stmt, "column_descriptions", [{}])[0].get("type") if hasattr(stmt, "column_descriptions") else None
        if target is TICache:
            return _FakeResult(self.existing_ti_cache)
        return _FakeResult(self.existing_endpoints)


def _incident(**overrides) -> Incident:
    fields = {"id": uuid.uuid4(), "tenant_id": uuid.uuid4(), "status": IncidentStatus.OPEN, "alert_ids": []}
    fields.update(overrides)
    return Incident(**fields)


def _mock_get_incident(monkeypatch, incident: Incident):
    monkeypatch.setattr("app.services.incident_evidence.get_incident", AsyncMock(return_value=incident))


def _mock_alerts(monkeypatch, alerts: list[dict]):
    monkeypatch.setattr("app.services.incident_evidence.get_alerts_by_ids", AsyncMock(return_value=alerts))


@pytest.mark.asyncio
async def test_raises_not_found_for_a_missing_incident(monkeypatch):
    from app.core.exceptions import IncidentNotFoundError as _NotFound

    monkeypatch.setattr(
        "app.services.incident_evidence.get_incident", AsyncMock(side_effect=_NotFound(uuid.uuid4()))
    )
    session = _FakeSession()

    with pytest.raises(IncidentNotFoundError):
        await get_incident_evidence(session, uuid.uuid4(), uuid.uuid4())


@pytest.mark.asyncio
async def test_extracts_distinct_hosts_ips_users(monkeypatch):
    incident = _incident()
    _mock_get_incident(monkeypatch, incident)
    alerts = [
        {"host_id": "H1", "source_ip": "1.1.1.1", "user": "alice", "source": "wazuh"},
        {"host_id": "H1", "source_ip": "1.1.1.1", "user": "alice", "source": "wazuh"},
        {"host_id": "H2", "source_ip": "2.2.2.2", "user": "bob", "source": "wazuh"},
    ]
    _mock_alerts(monkeypatch, alerts)
    session = _FakeSession()

    evidence = await get_incident_evidence(session, incident.tenant_id, incident.id)

    assert {h.host_id for h in evidence.hosts} == {"H1", "H2"}
    assert {ip.ip for ip in evidence.ips} == {"1.1.1.1", "2.2.2.2"}
    assert {u.user for u in evidence.users} == {"alice", "bob"}


@pytest.mark.asyncio
async def test_deduplicates_and_counts_repeated_hosts(monkeypatch):
    incident = _incident()
    _mock_get_incident(monkeypatch, incident)
    _mock_alerts(monkeypatch, [{"host_id": "H1"}, {"host_id": "H1"}, {"host_id": "H1"}])
    session = _FakeSession()

    evidence = await get_incident_evidence(session, incident.tenant_id, incident.id)

    assert len(evidence.hosts) == 1
    assert evidence.hosts[0].alert_count == 3


@pytest.mark.asyncio
async def test_host_annotated_with_endpoint_risk_data_when_available(monkeypatch):
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id=tenant_id)
    _mock_get_incident(monkeypatch, incident)
    _mock_alerts(monkeypatch, [{"host_id": "H1", "host_os": "windows"}])
    endpoint = Endpoint(id=uuid.uuid4(), tenant_id=tenant_id, host_id="H1", risk_score=87, risk_level=RiskLevel.HIGH)
    session = _FakeSession(existing_endpoints=[endpoint])

    evidence = await get_incident_evidence(session, tenant_id, incident.id)

    host = evidence.hosts[0]
    assert host.host_os == "windows"
    assert host.risk_score == 87
    assert host.risk_level == RiskLevel.HIGH


@pytest.mark.asyncio
async def test_host_with_no_endpoint_row_degrades_gracefully(monkeypatch):
    """AC: degrading gracefully when unavailable."""
    incident = _incident()
    _mock_get_incident(monkeypatch, incident)
    _mock_alerts(monkeypatch, [{"host_id": "H1"}])
    session = _FakeSession(existing_endpoints=[])

    evidence = await get_incident_evidence(session, incident.tenant_id, incident.id)

    host = evidence.hosts[0]
    assert host.risk_score is None
    assert host.risk_level is None


@pytest.mark.asyncio
async def test_ip_annotated_malicious_when_ti_cache_says_so(monkeypatch):
    incident = _incident()
    _mock_get_incident(monkeypatch, incident)
    _mock_alerts(monkeypatch, [{"source_ip": "9.9.9.9"}])
    ti_row = TICache(
        id=uuid.uuid4(), indicator="9.9.9.9", provider=TIProvider.ABUSEIPDB, result={}, is_malicious=True,
        expires_at=None,
    )
    session = _FakeSession(existing_ti_cache=[ti_row])

    evidence = await get_incident_evidence(session, incident.tenant_id, incident.id)

    assert evidence.ips[0].is_malicious is True


@pytest.mark.asyncio
async def test_ip_annotated_clean_when_ti_cache_verdict_is_clean(monkeypatch):
    incident = _incident()
    _mock_get_incident(monkeypatch, incident)
    _mock_alerts(monkeypatch, [{"source_ip": "8.8.8.8"}])
    ti_row = TICache(
        id=uuid.uuid4(), indicator="8.8.8.8", provider=TIProvider.VIRUSTOTAL, result={}, is_malicious=False,
        expires_at=None,
    )
    session = _FakeSession(existing_ti_cache=[ti_row])

    evidence = await get_incident_evidence(session, incident.tenant_id, incident.id)

    assert evidence.ips[0].is_malicious is False


@pytest.mark.asyncio
async def test_ip_with_no_ti_cache_row_degrades_gracefully(monkeypatch):
    """AC: degrading gracefully when unavailable — never checked, not assumed clean."""
    incident = _incident()
    _mock_get_incident(monkeypatch, incident)
    _mock_alerts(monkeypatch, [{"source_ip": "3.3.3.3"}])
    session = _FakeSession(existing_ti_cache=[])

    evidence = await get_incident_evidence(session, incident.tenant_id, incident.id)

    assert evidence.ips[0].is_malicious is None


@pytest.mark.asyncio
async def test_ip_appearing_as_both_source_and_destination_records_both_roles(monkeypatch):
    incident = _incident()
    _mock_get_incident(monkeypatch, incident)
    _mock_alerts(
        monkeypatch,
        [
            {"source_ip": "5.5.5.5"},
            {"destination_ip": "5.5.5.5"},
        ],
    )
    session = _FakeSession()

    evidence = await get_incident_evidence(session, incident.tenant_id, incident.id)

    assert len(evidence.ips) == 1
    assert evidence.ips[0].roles == ["destination", "source"]
    assert evidence.ips[0].alert_count == 2


@pytest.mark.asyncio
async def test_cloudlens_alerts_become_cloud_resources_not_hosts(monkeypatch):
    incident = _incident()
    _mock_get_incident(monkeypatch, incident)
    _mock_alerts(
        monkeypatch,
        [
            {"host_id": "arn:aws:iam::123:role/Admin", "source": "cloudlens"},
            {"host_id": "DESKTOP-01", "source": "wazuh"},
        ],
    )
    session = _FakeSession()

    evidence = await get_incident_evidence(session, incident.tenant_id, incident.id)

    assert {r.resource_id for r in evidence.cloud_resources} == {"arn:aws:iam::123:role/Admin"}
    assert {h.host_id for h in evidence.hosts} == {"DESKTOP-01"}


@pytest.mark.asyncio
async def test_unknown_user_is_not_extracted_as_an_entity(monkeypatch):
    """NormalizedLog defaults `user` to "unknown" when absent — not a real entity worth surfacing."""
    incident = _incident()
    _mock_get_incident(monkeypatch, incident)
    _mock_alerts(monkeypatch, [{"user": "unknown"}])
    session = _FakeSession()

    evidence = await get_incident_evidence(session, incident.tenant_id, incident.id)

    assert evidence.users == []


@pytest.mark.asyncio
async def test_incident_with_no_alerts_produces_empty_evidence(monkeypatch):
    incident = _incident()
    _mock_get_incident(monkeypatch, incident)
    _mock_alerts(monkeypatch, [])
    session = _FakeSession()

    evidence = await get_incident_evidence(session, incident.tenant_id, incident.id)

    assert evidence.hosts == []
    assert evidence.ips == []
    assert evidence.users == []
    assert evidence.cloud_resources == []
