"""
SafeSOC — OpenSearch Client & Health Endpoint Tests
"""

import re
from datetime import datetime
from unittest.mock import AsyncMock

import pytest
from opensearchpy import exceptions

from app.core.config import settings
from app.db.mappings.ilm_policy import ILM_POLICY, ILM_POLICY_ID
from app.db.opensearch import _build_index_name, check_connection, ensure_ilm_policy, get_cloud_summary


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
    monkeypatch.setattr("app.routers.health.check_postgres", AsyncMock(return_value=True))
    monkeypatch.setattr("app.routers.health.check_redis", AsyncMock(return_value=True))

    response = client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "healthy"
    assert body["checks"]["opensearch"] == "connected"
    assert body["checks"]["postgresql"] == "connected"
    assert body["checks"]["redis"] == "connected"


def test_health_degraded_when_postgres_unreachable(client, monkeypatch):
    monkeypatch.setattr("app.routers.health.check_opensearch", AsyncMock(return_value=True))
    monkeypatch.setattr("app.routers.health.check_postgres", AsyncMock(return_value=False))
    monkeypatch.setattr("app.routers.health.check_redis", AsyncMock(return_value=True))

    response = client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "degraded"
    assert body["checks"]["opensearch"] == "connected"
    assert body["checks"]["postgresql"] == "unavailable"


def test_health_degraded_when_redis_unreachable(client, monkeypatch):
    monkeypatch.setattr("app.routers.health.check_opensearch", AsyncMock(return_value=True))
    monkeypatch.setattr("app.routers.health.check_postgres", AsyncMock(return_value=True))
    monkeypatch.setattr("app.routers.health.check_redis", AsyncMock(return_value=False))

    response = client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "degraded"
    assert body["checks"]["postgresql"] == "connected"
    assert body["checks"]["redis"] == "unavailable"


# ── ILM policy (SS-006) ────────────────────────────────────────

def test_ilm_policy_targets_alert_indices_with_configured_retention():
    assert ILM_POLICY["policy"]["ism_template"][0]["index_patterns"] == ["safesoc-alerts-*"]
    transitions = ILM_POLICY["policy"]["states"][0]["transitions"]
    assert transitions[0]["conditions"]["min_index_age"] == f"{settings.OPENSEARCH_ILM_RETENTION_DAYS}d"


class _FakeIndexManagement:
    """Fake index_management client tracking put_policy calls."""

    def __init__(self, policy_exists: bool):
        self._policy_exists = policy_exists
        self.put_calls: list[tuple] = []

    def get_policy(self, policy):
        if not self._policy_exists:
            raise exceptions.NotFoundError(404, "not_found", {})
        return {"policy": {}}

    def put_policy(self, policy, body):
        self.put_calls.append((policy, body))


@pytest.mark.asyncio
async def test_ensure_ilm_policy_creates_when_missing(monkeypatch):
    fake_im = _FakeIndexManagement(policy_exists=False)
    fake_client = type("FakeClient", (), {"index_management": fake_im})()
    monkeypatch.setattr("app.db.opensearch.get_client", lambda: fake_client)

    await ensure_ilm_policy()

    assert len(fake_im.put_calls) == 1
    policy_id, body = fake_im.put_calls[0]
    assert policy_id == ILM_POLICY_ID
    assert body == ILM_POLICY


@pytest.mark.asyncio
async def test_ensure_ilm_policy_skips_when_already_exists(monkeypatch):
    fake_im = _FakeIndexManagement(policy_exists=True)
    fake_client = type("FakeClient", (), {"index_management": fake_im})()
    monkeypatch.setattr("app.db.opensearch.get_client", lambda: fake_client)

    await ensure_ilm_policy()  # must not raise

    assert fake_im.put_calls == []


# ── SS-040: get_cloud_summary ────────────────────────────────

class _FakeSearchClient:
    def __init__(self, response):
        self._response = response
        self.last_search_kwargs = None

    def search(self, index, body):
        self.last_search_kwargs = {"index": index, "body": body}
        return self._response


@pytest.mark.asyncio
async def test_get_cloud_summary_parses_aggregation_buckets_into_dicts(monkeypatch):
    fake_response = {
        "hits": {"total": {"value": 5}},
        "aggregations": {
            "by_severity": {"buckets": [{"key": "critical", "doc_count": 2}, {"key": "high", "doc_count": 3}]},
            "by_category": {"buckets": [{"key": "Privilege Escalation", "doc_count": 5}]},
            "distinct_affected_resources": {"value": 4},
        },
    }
    fake_client = _FakeSearchClient(fake_response)
    monkeypatch.setattr("app.db.opensearch.get_client", lambda: fake_client)

    result = await get_cloud_summary("acme-corp", timerange_hours=48)

    assert result == {
        "total": 5,
        "by_severity": {"critical": 2, "high": 3},
        "by_category": {"Privilege Escalation": 5},
        "distinct_affected_resources": 4,
    }


@pytest.mark.asyncio
async def test_get_cloud_summary_scopes_the_query_to_tenant_and_cloudlens_source(monkeypatch):
    fake_response = {
        "hits": {"total": {"value": 0}},
        "aggregations": {
            "by_severity": {"buckets": []},
            "by_category": {"buckets": []},
            "distinct_affected_resources": {"value": 0},
        },
    }
    fake_client = _FakeSearchClient(fake_response)
    monkeypatch.setattr("app.db.opensearch.get_client", lambda: fake_client)

    await get_cloud_summary("acme-corp")

    must_filters = fake_client.last_search_kwargs["body"]["query"]["bool"]["must"]
    assert {"term": {"tenant_id": "acme-corp"}} in must_filters
    assert {"term": {"source": "cloudlens"}} in must_filters
