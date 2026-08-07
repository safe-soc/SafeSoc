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
    RiskyEndpointsOutput,
)
from app.models.endpoint import Endpoint
from app.models.incident import Incident


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
    mock_search.assert_called_once_with(
        tenant_id=str(tenant_id), action="failed_login", host_id="DESKTOP-042", timerange_hours=24, size=100
    )


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
    mock_list.assert_called_once_with(None, tenant_id, status=IncidentStatus.OPEN)
