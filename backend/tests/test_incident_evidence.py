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


# ── SS-103: host anomaly flag ────────────────────────────────────────
# Uses settings.ANOMALY_THRESHOLD (default 0.7, see core/config.py) —
# the same threshold services/anomaly.py itself uses for is_anomalous,
# not a new one invented for this issue.

@pytest.mark.asyncio
async def test_host_flagged_anomalous_when_an_alert_meets_the_threshold(monkeypatch):
    incident = _incident()
    _mock_get_incident(monkeypatch, incident)
    _mock_alerts(monkeypatch, [{"host_id": "H1", "anomaly_score": 0.85}])
    session = _FakeSession()

    evidence = await get_incident_evidence(session, incident.tenant_id, incident.id)

    assert evidence.hosts[0].has_anomalous_activity is True


@pytest.mark.asyncio
async def test_host_flagged_anomalous_at_exactly_the_threshold(monkeypatch):
    incident = _incident()
    _mock_get_incident(monkeypatch, incident)
    _mock_alerts(monkeypatch, [{"host_id": "H1", "anomaly_score": 0.7}])
    session = _FakeSession()

    evidence = await get_incident_evidence(session, incident.tenant_id, incident.id)

    assert evidence.hosts[0].has_anomalous_activity is True


@pytest.mark.asyncio
async def test_host_not_flagged_when_below_the_threshold(monkeypatch):
    incident = _incident()
    _mock_get_incident(monkeypatch, incident)
    _mock_alerts(monkeypatch, [{"host_id": "H1", "anomaly_score": 0.3}])
    session = _FakeSession()

    evidence = await get_incident_evidence(session, incident.tenant_id, incident.id)

    assert evidence.hosts[0].has_anomalous_activity is False


@pytest.mark.asyncio
async def test_host_not_flagged_when_never_scored(monkeypatch):
    """AC: degrades gracefully — no anomaly_score at all is not treated as anomalous."""
    incident = _incident()
    _mock_get_incident(monkeypatch, incident)
    _mock_alerts(monkeypatch, [{"host_id": "H1", "anomaly_score": None}])
    session = _FakeSession()

    evidence = await get_incident_evidence(session, incident.tenant_id, incident.id)

    assert evidence.hosts[0].has_anomalous_activity is False


@pytest.mark.asyncio
async def test_host_flagged_if_any_one_of_its_alerts_is_anomalous(monkeypatch):
    incident = _incident()
    _mock_get_incident(monkeypatch, incident)
    _mock_alerts(
        monkeypatch,
        [{"host_id": "H1", "anomaly_score": 0.1}, {"host_id": "H1", "anomaly_score": 0.9}],
    )
    session = _FakeSession()

    evidence = await get_incident_evidence(session, incident.tenant_id, incident.id)

    assert evidence.hosts[0].has_anomalous_activity is True
    assert evidence.hosts[0].alert_count == 2


# ── Per-IP threat-intel details ─────────────────────────────────────

def _ti_row(ip: str, provider: TIProvider, result: dict, is_malicious: bool, created_at=None) -> TICache:
    return TICache(id=uuid.uuid4(), indicator=ip, provider=provider, result=result, is_malicious=is_malicious, expires_at=None, created_at=created_at)


@pytest.mark.asyncio
async def test_ip_ti_carries_each_provider_details_from_its_own_row(monkeypatch):
    from datetime import datetime, timezone

    incident = _incident()
    _mock_get_incident(monkeypatch, incident)
    _mock_alerts(monkeypatch, [{"source_ip": "140.246.61.93"}])
    earlier = datetime(2026, 10, 1, tzinfo=timezone.utc)
    later = datetime(2026, 10, 2, tzinfo=timezone.utc)
    # Each row also carries a decoy of the OTHER provider's block, which
    # must be ignored — vt only from VT's row, abuse only from AbuseIPDB's.
    vt_row = _ti_row("140.246.61.93", TIProvider.VIRUSTOTAL, {"vt": {"malicious": 4, "as_owner": "VT owner"}, "abuse": {"isp": "WRONG"}}, True, earlier)
    abuse_row = _ti_row("140.246.61.93", TIProvider.ABUSEIPDB, {"abuse": {"confidence": 12, "isp": "Abuse ISP"}, "vt": {"as_owner": "WRONG"}}, False, later)
    session = _FakeSession(existing_ti_cache=[vt_row, abuse_row])

    evidence = await get_incident_evidence(session, incident.tenant_id, incident.id)

    ip = evidence.ips[0]
    assert ip.is_malicious is True
    assert ip.ti.is_malicious is True
    assert ip.ti.checked_at == later
    assert ip.ti.vt.malicious == 4 and ip.ti.vt.as_owner == "VT owner"
    assert ip.ti.abuse.confidence == 12 and ip.ti.abuse.isp == "Abuse ISP"


@pytest.mark.asyncio
async def test_ip_ti_with_only_an_abuseipdb_row_has_no_vt(monkeypatch):
    incident = _incident()
    _mock_get_incident(monkeypatch, incident)
    _mock_alerts(monkeypatch, [{"source_ip": "140.246.61.93"}])
    session = _FakeSession(existing_ti_cache=[_ti_row("140.246.61.93", TIProvider.ABUSEIPDB, {"abuse": {"confidence": 0}}, False)])

    evidence = await get_incident_evidence(session, incident.tenant_id, incident.id)

    ip = evidence.ips[0]
    assert ip.is_malicious is False
    assert ip.ti.vt is None
    assert ip.ti.abuse.confidence == 0


@pytest.mark.asyncio
async def test_ip_ti_is_none_with_no_rows(monkeypatch):
    incident = _incident()
    _mock_get_incident(monkeypatch, incident)
    _mock_alerts(monkeypatch, [{"source_ip": "140.246.61.93"}])
    session = _FakeSession(existing_ti_cache=[])

    evidence = await get_incident_evidence(session, incident.tenant_id, incident.id)

    assert evidence.ips[0].ti is None
    assert evidence.ips[0].is_malicious is None


@pytest.mark.asyncio
async def test_old_format_cache_rows_without_details_still_deserialize(monkeypatch):
    incident = _incident()
    _mock_get_incident(monkeypatch, incident)
    _mock_alerts(monkeypatch, [{"source_ip": "140.246.61.93"}])
    old_vt = _ti_row("140.246.61.93", TIProvider.VIRUSTOTAL, {"source_ip": "140.246.61.93", "vt_malicious": 0, "vt_total": 70, "is_malicious": False, "tags": []}, False)
    old_abuse = _ti_row("140.246.61.93", TIProvider.ABUSEIPDB, {"source_ip": "140.246.61.93", "abuse_confidence": 0, "abuse_total_reports": 0, "is_malicious": False, "tags": []}, False)
    session = _FakeSession(existing_ti_cache=[old_vt, old_abuse])

    evidence = await get_incident_evidence(session, incident.tenant_id, incident.id)

    ip = evidence.ips[0]
    assert ip.ti is not None
    assert ip.ti.vt is None and ip.ti.abuse is None
    assert ip.ti.checked_at is None
    assert ip.is_malicious is False


@pytest.mark.asyncio
@pytest.mark.parametrize(("ip", "expected"), [("203.0.113.5", False), ("10.0.0.1", False), ("140.246.61.93", True), ("not-an-ip", False)])
async def test_is_public_reflects_global_routability(monkeypatch, ip, expected):
    incident = _incident()
    _mock_get_incident(monkeypatch, incident)
    _mock_alerts(monkeypatch, [{"source_ip": ip}])

    evidence = await get_incident_evidence(_FakeSession(), incident.tenant_id, incident.id)

    assert evidence.ips[0].is_public is expected
