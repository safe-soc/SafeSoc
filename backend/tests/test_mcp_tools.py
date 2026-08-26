"""
SafeSOC — MCP Tool Definition Tests
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from app.core.enums import Intent, IncidentStatus, RiskLevel
from app.mcp import TOOLS
from app.mcp.tools import (
    AlertListOutput,
    AttackChainStatusOutput,
    EndpointSnapshotOutput,
    IncidentNarrativeDataInput,
    RiskyEndpointsOutput,
    incident_narrative_data,
)
from app.core.exceptions import IncidentNotFoundError
from app.models.endpoint import Endpoint
from app.models.incident import Incident
from app.schemas.incidents import TimelineEntry
from app.services.incident_evidence import HostEntity, IncidentEvidence


# ── SS-045 AC: each of the 8 intents has a corresponding tool ────────

def test_every_intent_has_a_tool_except_unknown():
    assert set(TOOLS.keys()) == set(Intent) - {Intent.UNKNOWN}


def test_every_tool_has_a_name_description_and_typed_schemas():
    for intent, tool in TOOLS.items():
        assert tool.intent == intent
        assert tool.name
        assert tool.description
        assert tool.input_model is not None
        assert tool.output_model is not None


# ── auth_failures ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_auth_failures_queries_search_alerts_with_failed_login_action(monkeypatch):
    mock_search = AsyncMock(return_value={"total": 2, "alerts": [{"alert_id": "a1"}, {"alert_id": "a2"}]})
    monkeypatch.setattr("app.mcp.tools.search_alerts", mock_search)
    tenant_id = uuid.uuid4()

    result = await TOOLS[Intent.AUTH_FAILURES].call(None, tenant_id, {"host_id": "DESKTOP-042"})

    assert isinstance(result, AlertListOutput)
    assert result.total == 2
    assert result.truncated is False  # total == len(alerts) — nothing left out
    mock_search.assert_called_once_with(
        tenant_id=str(tenant_id), action="failed_login", host_id="DESKTOP-042", timerange_hours=24, size=100
    )


# ── truncation metadata (SS-086) ──────────────────────────────────
# Exercised once via a single AlertListOutput-backed tool, since all
# five (auth_failures, ip_activity, top_alerts, user_activity,
# cloud_events) share the exact same _alert_list_output() helper.

@pytest.mark.asyncio
async def test_alert_list_tool_reports_truncated_when_total_exceeds_returned_alerts(monkeypatch):
    mock_search = AsyncMock(return_value={"total": 150, "alerts": [{"alert_id": "a1"}, {"alert_id": "a2"}]})
    monkeypatch.setattr("app.mcp.tools.search_alerts", mock_search)

    result = await TOOLS[Intent.AUTH_FAILURES].call(None, uuid.uuid4(), {})

    assert result.total == 150
    assert len(result.alerts) == 2
    assert result.truncated is True


# ── ip_activity ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ip_activity_queries_search_alerts_by_source_ip(monkeypatch):
    mock_search = AsyncMock(return_value={"total": 1, "alerts": [{"alert_id": "a1"}]})
    monkeypatch.setattr("app.mcp.tools.search_alerts", mock_search)
    tenant_id = uuid.uuid4()

    result = await TOOLS[Intent.IP_ACTIVITY].call(None, tenant_id, {"ip": "45.33.32.156"})

    assert result.total == 1
    mock_search.assert_called_once_with(
        tenant_id=str(tenant_id), source_ip="45.33.32.156", timerange_hours=24, size=100
    )


@pytest.mark.asyncio
async def test_ip_activity_requires_an_ip():
    with pytest.raises(Exception):  # pydantic ValidationError — "ip" is a required field
        await TOOLS[Intent.IP_ACTIVITY].call(None, uuid.uuid4(), {})


# ── endpoint_snapshot ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_endpoint_snapshot_combines_risk_score_and_recent_alerts(monkeypatch):
    now = datetime.now(timezone.utc)
    endpoint = Endpoint(
        id=uuid.uuid4(), tenant_id=uuid.uuid4(), host_id="DESKTOP-042",
        risk_score=65, risk_level=RiskLevel.HIGH, updated_at=now,
    )
    monkeypatch.setattr("app.mcp.tools.get_endpoint", AsyncMock(return_value=endpoint))
    monkeypatch.setattr(
        "app.mcp.tools.search_alerts",
        AsyncMock(return_value={"total": 3, "alerts": [{"alert_id": "a1"}, {"alert_id": "a2"}, {"alert_id": "a3"}]}),
    )

    result = await TOOLS[Intent.ENDPOINT_SNAPSHOT].call(None, uuid.uuid4(), {"host_id": "DESKTOP-042"})

    assert isinstance(result, EndpointSnapshotOutput)
    assert result.risk_score == 65
    assert result.risk_level == RiskLevel.HIGH
    assert result.recent_alert_count == 3
    assert result.truncated is False  # recent_alert_count == len(recent_alerts)


@pytest.mark.asyncio
async def test_endpoint_snapshot_reports_truncated_when_recent_alert_count_exceeds_returned_alerts(monkeypatch):
    monkeypatch.setattr(
        "app.mcp.tools.get_endpoint",
        AsyncMock(return_value=Endpoint(
            id=uuid.uuid4(), tenant_id=uuid.uuid4(), host_id="DESKTOP-042",
            risk_score=65, risk_level=RiskLevel.HIGH, updated_at=datetime.now(timezone.utc),
        )),
    )
    monkeypatch.setattr(
        "app.mcp.tools.search_alerts",
        AsyncMock(return_value={"total": 25, "alerts": [{"alert_id": "a1"}, {"alert_id": "a2"}]}),
    )

    result = await TOOLS[Intent.ENDPOINT_SNAPSHOT].call(None, uuid.uuid4(), {"host_id": "DESKTOP-042"})

    assert result.recent_alert_count == 25
    assert len(result.recent_alerts) == 2
    assert result.truncated is True


@pytest.mark.asyncio
async def test_endpoint_snapshot_degrades_gracefully_for_a_never_scored_host(monkeypatch):
    monkeypatch.setattr("app.mcp.tools.get_endpoint", AsyncMock(return_value=None))
    monkeypatch.setattr("app.mcp.tools.search_alerts", AsyncMock(return_value={"total": 0, "alerts": []}))

    result = await TOOLS[Intent.ENDPOINT_SNAPSHOT].call(None, uuid.uuid4(), {"host_id": "NEVER-SEEN"})

    assert result.risk_score is None
    assert result.risk_level is None
    assert result.recent_alert_count == 0


# ── top_alerts ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_top_alerts_passes_through_severity_filter(monkeypatch):
    mock_search = AsyncMock(return_value={"total": 5, "alerts": []})
    monkeypatch.setattr("app.mcp.tools.search_alerts", mock_search)
    tenant_id = uuid.uuid4()

    await TOOLS[Intent.TOP_ALERTS].call(None, tenant_id, {"severity": "critical"})

    mock_search.assert_called_once_with(tenant_id=str(tenant_id), severity="critical", timerange_hours=24, size=20)


# ── user_activity ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_user_activity_queries_search_alerts_by_user(monkeypatch):
    mock_search = AsyncMock(return_value={"total": 4, "alerts": []})
    monkeypatch.setattr("app.mcp.tools.search_alerts", mock_search)
    tenant_id = uuid.uuid4()

    await TOOLS[Intent.USER_ACTIVITY].call(None, tenant_id, {"user": "john.doe"})

    mock_search.assert_called_once_with(tenant_id=str(tenant_id), user="john.doe", timerange_hours=24, size=100)


# ── cloud_events ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_cloud_events_queries_search_alerts_by_cloudlens_source(monkeypatch):
    mock_search = AsyncMock(return_value={"total": 2, "alerts": []})
    monkeypatch.setattr("app.mcp.tools.search_alerts", mock_search)
    tenant_id = uuid.uuid4()

    await TOOLS[Intent.CLOUD_EVENTS].call(None, tenant_id, {})

    mock_search.assert_called_once_with(tenant_id=str(tenant_id), source="cloudlens", timerange_hours=24, size=50)


# ── risky_endpoints ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_risky_endpoints_reuses_list_endpoints_and_respects_limit(monkeypatch):
    now = datetime.now(timezone.utc)
    endpoints = [
        Endpoint(id=uuid.uuid4(), tenant_id=uuid.uuid4(), host_id=f"HOST-{i}", risk_score=100 - i, risk_level=RiskLevel.HIGH, updated_at=now)
        for i in range(5)
    ]
    monkeypatch.setattr("app.mcp.tools.list_endpoints", AsyncMock(return_value=endpoints))

    result = await TOOLS[Intent.RISKY_ENDPOINTS].call(None, uuid.uuid4(), {"limit": 2})

    assert isinstance(result, RiskyEndpointsOutput)
    assert len(result.endpoints) == 2
    assert result.endpoints[0]["host_id"] == "HOST-0"
    assert result.truncated is True  # 5 known endpoints, limit=2 — 3 were left out


@pytest.mark.asyncio
async def test_risky_endpoints_reports_not_truncated_when_the_limit_covers_every_endpoint(monkeypatch):
    now = datetime.now(timezone.utc)
    endpoints = [
        Endpoint(id=uuid.uuid4(), tenant_id=uuid.uuid4(), host_id="HOST-0", risk_score=90, risk_level=RiskLevel.HIGH, updated_at=now),
    ]
    monkeypatch.setattr("app.mcp.tools.list_endpoints", AsyncMock(return_value=endpoints))

    result = await TOOLS[Intent.RISKY_ENDPOINTS].call(None, uuid.uuid4(), {"limit": 10})

    assert result.truncated is False


# ── attack_chain_status ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_attack_chain_status_reuses_list_incidents(monkeypatch):
    now = datetime.now(timezone.utc)
    incident = Incident(
        id=uuid.uuid4(), tenant_id=uuid.uuid4(), status=IncidentStatus.OPEN, alert_ids=["a1", "a2"],
        created_at=now, updated_at=now,
    )
    mock_list = AsyncMock(return_value=([incident], 1))
    monkeypatch.setattr("app.mcp.tools.list_incidents", mock_list)
    tenant_id = uuid.uuid4()

    result = await TOOLS[Intent.ATTACK_CHAIN_STATUS].call(None, tenant_id, {"status": "open"})

    assert isinstance(result, AttackChainStatusOutput)
    assert result.total == 1
    assert result.incidents[0]["alert_ids"] == ["a1", "a2"]
    assert result.truncated is False  # total == len(incidents)
    mock_list.assert_called_once_with(None, tenant_id, status=IncidentStatus.OPEN)


@pytest.mark.asyncio
async def test_attack_chain_status_reports_truncated_when_total_exceeds_returned_incidents(monkeypatch):
    now = datetime.now(timezone.utc)
    incident = Incident(
        id=uuid.uuid4(), tenant_id=uuid.uuid4(), status=IncidentStatus.OPEN, alert_ids=["a1"],
        created_at=now, updated_at=now,
    )
    # list_incidents defaults to size=50 — simulate more real matches than the page returned.
    monkeypatch.setattr("app.mcp.tools.list_incidents", AsyncMock(return_value=([incident], 75)))

    result = await TOOLS[Intent.ATTACK_CHAIN_STATUS].call(None, uuid.uuid4(), {})

    assert result.total == 75
    assert len(result.incidents) == 1
    assert result.truncated is True


# ── incident_narrative_data (SS-109) ─────────────────────────────────
# Not registered in TOOLS/Intent — invoked directly, so these call the
# function itself rather than going through TOOLS[...].call().

def _incident(**overrides):
    now = datetime.now(timezone.utc)
    fields = {
        "id": uuid.uuid4(), "tenant_id": uuid.uuid4(), "status": IncidentStatus.OPEN, "alert_ids": [],
        "confidence": None, "created_at": now, "updated_at": now,
    }
    fields.update(overrides)
    return Incident(**fields)


def _mock_narrative_sources(monkeypatch, incident, timeline=None, evidence=None):
    monkeypatch.setattr("app.mcp.tools.get_incident", AsyncMock(return_value=incident))
    monkeypatch.setattr("app.mcp.tools.get_incident_timeline", AsyncMock(return_value=timeline or []))
    monkeypatch.setattr(
        "app.mcp.tools.get_incident_evidence",
        AsyncMock(return_value=evidence or IncidentEvidence(incident_id=incident.id, hosts=[], ips=[], users=[], cloud_resources=[])),
    )


@pytest.mark.asyncio
async def test_incident_narrative_data_raises_not_found_for_a_missing_incident(monkeypatch):
    monkeypatch.setattr(
        "app.mcp.tools.get_incident", AsyncMock(side_effect=IncidentNotFoundError(uuid.uuid4()))
    )

    with pytest.raises(IncidentNotFoundError):
        await incident_narrative_data(None, uuid.uuid4(), IncidentNarrativeDataInput(incident_id=uuid.uuid4()))


@pytest.mark.asyncio
async def test_incident_narrative_data_aggregates_timeline_and_evidence(monkeypatch):
    incident = _incident(confidence=0.85)
    timeline = [
        TimelineEntry(type="alert", timestamp=datetime.now(timezone.utc), data={"host_id": "H1"}),
        TimelineEntry(type="note", timestamp=datetime.now(timezone.utc), data={"body": "Confirmed."}),
    ]
    evidence = IncidentEvidence(
        incident_id=incident.id,
        hosts=[HostEntity(host_id="H1", alert_count=1)],
        ips=[], users=[], cloud_resources=[],
    )
    _mock_narrative_sources(monkeypatch, incident, timeline=timeline, evidence=evidence)

    result = await incident_narrative_data(None, incident.tenant_id, IncidentNarrativeDataInput(incident_id=incident.id))

    assert result.incident_id == incident.id
    assert len(result.events) == 2
    assert result.events[0].type == "alert"
    assert result.hosts == [{"host_id": "H1", "host_os": None, "risk_score": None, "risk_level": None, "alert_count": 1, "has_anomalous_activity": False}]
    assert result.confidence == 0.85


@pytest.mark.asyncio
async def test_incident_narrative_data_dedupes_and_sorts_mitre_techniques(monkeypatch):
    incident = _incident()
    timeline = [
        TimelineEntry(type="alert", timestamp=datetime.now(timezone.utc), data={"mitre_technique": "T1110"}),
        TimelineEntry(type="alert", timestamp=datetime.now(timezone.utc), data={"mitre_technique": "T1078"}),
        TimelineEntry(type="alert", timestamp=datetime.now(timezone.utc), data={"mitre_technique": "T1110"}),
        TimelineEntry(type="note", timestamp=datetime.now(timezone.utc), data={"mitre_technique": "should-be-ignored"}),
    ]
    _mock_narrative_sources(monkeypatch, incident, timeline=timeline)

    result = await incident_narrative_data(None, incident.tenant_id, IncidentNarrativeDataInput(incident_id=incident.id))

    assert result.mitre_techniques == ["T1078", "T1110"]


@pytest.mark.asyncio
async def test_incident_narrative_data_handles_an_incident_with_no_activity(monkeypatch):
    incident = _incident()
    _mock_narrative_sources(monkeypatch, incident)

    result = await incident_narrative_data(None, incident.tenant_id, IncidentNarrativeDataInput(incident_id=incident.id))

    assert result.events == []
    assert result.hosts == []
    assert result.mitre_techniques == []
    assert result.confidence is None
