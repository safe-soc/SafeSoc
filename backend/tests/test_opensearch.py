"""
SafeSOC — OpenSearch Client & Health Endpoint Tests
"""

import re
from datetime import datetime
from unittest.mock import AsyncMock

import pytest

from app.db.opensearch import _build_index_name, check_connection


# ── _build_index_name ────────────────────────────────────────

def test_build_index_name_specific_month():
    assert _build_index_name(datetime(2026, 5, 12)) == "safesoc-alerts-2026.05"


def test_build_index_name_pads_single_digit_month():
    assert _build_index_name(datetime(2026, 3, 5)) == "safesoc-alerts-2026.03"


def test_build_index_name_december_year_boundary():
    assert _build_index_name(datetime(2025, 12, 31, 23, 59)) == "safesoc-alerts-2025.12"


def test_build_index_name_january_year_boundary():
    assert _build_index_name(datetime(2026, 1, 1, 0, 0)) == "safesoc-alerts-2026.01"


def test_build_index_name_defaults_to_current_time_when_omitted():
    result = _build_index_name()
    assert re.match(r"^safesoc-alerts-\d{4}\.\d{2}$", result)


# ── check_connection ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_check_connection_true_when_ping_succeeds(monkeypatch):
    fake_client = type("FakeClient", (), {"ping": lambda self: True})()
    monkeypatch.setattr("app.db.opensearch.get_client", lambda: fake_client)

    assert await check_connection() is True


@pytest.mark.asyncio
async def test_check_connection_false_when_ping_fails(monkeypatch):
    fake_client = type("FakeClient", (), {"ping": lambda self: False})()
    monkeypatch.setattr("app.db.opensearch.get_client", lambda: fake_client)

    assert await check_connection() is False


@pytest.mark.asyncio
async def test_check_connection_false_when_client_raises(monkeypatch):
    def _raise():
        raise ConnectionError("no route to host")

    monkeypatch.setattr("app.db.opensearch.get_client", _raise)

    assert await check_connection() is False


# ── GET /health (degraded-state behavior) ─────────────────────

def test_health_degraded_when_opensearch_unreachable(client, mock_opensearch_unreachable):
    response = client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "degraded"
    assert body["checks"]["opensearch"] == "unavailable"


def test_health_healthy_when_opensearch_reachable(client, monkeypatch):
    monkeypatch.setattr("app.routers.health.check_opensearch", AsyncMock(return_value=True))

    response = client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "healthy"
    assert body["checks"]["opensearch"] == "connected"
