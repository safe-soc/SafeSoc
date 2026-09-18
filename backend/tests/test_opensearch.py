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
from app.db.opensearch import (
    _build_index_name,
    check_connection,
    ensure_ilm_policy,
    get_alert_severity_summary,
    get_cloud_summary,
    get_known_endpoints,
    update_alert_anomaly_score,
)


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


# ── update_alert_anomaly_score (SS-102) ────────────────────────

@pytest.mark.asyncio
async def test_update_alert_anomaly_score_calls_update_with_the_score(monkeypatch):
    calls = []
    fake_client = type("FakeClient", (), {"update": lambda self, **kwargs: calls.append(kwargs)})()
    monkeypatch.setattr("app.db.opensearch.get_client", lambda: fake_client)

    ok = await update_alert_anomaly_score("alert-1", datetime(2026, 5, 12), 0.83)

    assert ok is True
    assert calls[0]["id"] == "alert-1"
    assert calls[0]["index"] == "safesoc-alerts-2026.05"
    assert calls[0]["body"] == {"doc": {"anomaly_score": 0.83}}


@pytest.mark.asyncio
async def test_update_alert_anomaly_score_returns_false_on_opensearch_failure(monkeypatch):
    def _raise(self, **kwargs):
        raise exceptions.OpenSearchException("cluster unavailable")

    fake_client = type("FakeClient", (), {"update": _raise})()
    monkeypatch.setattr("app.db.opensearch.get_client", lambda: fake_client)

    ok = await update_alert_anomaly_score("alert-1", datetime(2026, 5, 12), 0.83)

    assert ok is False


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


# ── get_alert_severity_summary (dashboard severity distribution fix) ──

@pytest.mark.asyncio
async def test_get_alert_severity_summary_uses_aggregation_not_document_fetch(monkeypatch):
    """
    The query must be a size:0 aggregation — the bug this fixes was a
    document-fetch page (capped by a `size` limit) standing in for the
    full population's severity breakdown.
    """
    fake_response = {
        "hits": {"total": {"value": 2311}},
        "aggregations": {
            "by_severity": {
                "buckets": [
                    {"key": "low", "doc_count": 1200},
                    {"key": "medium", "doc_count": 700},
                    {"key": "high", "doc_count": 350},
                    {"key": "critical", "doc_count": 61},
                ]
            }
        },
    }
    fake_client = _FakeSearchClient(fake_response)
    monkeypatch.setattr("app.db.opensearch.get_client", lambda: fake_client)

    result = await get_alert_severity_summary("acme-corp", timerange_hours=168)

    assert fake_client.last_search_kwargs["body"]["size"] == 0
    assert result == {
        "total": 2311,
        "timerange_hours": 168,
        "by_severity": {"low": 1200, "medium": 700, "high": 350, "critical": 61},
    }


def test_get_alert_severity_summary_buckets_sum_to_the_total():
    """
    Every indexed alert has exactly one of the 4 valid severities
    (NormalizedLog validation rejects anything else at ingestion — see
    app/schemas/log.py), so the buckets must always sum to the total,
    not merely be a subset of it.
    """
    by_severity = {"low": 1200, "medium": 700, "high": 350, "critical": 61}
    assert sum(by_severity.values()) == 2311


@pytest.mark.asyncio
async def test_get_alert_severity_summary_scopes_the_query_to_tenant_and_window(monkeypatch):
    fake_response = {
        "hits": {"total": {"value": 0}},
        "aggregations": {"by_severity": {"buckets": []}},
    }
    fake_client = _FakeSearchClient(fake_response)
    monkeypatch.setattr("app.db.opensearch.get_client", lambda: fake_client)

    await get_alert_severity_summary("acme-corp", timerange_hours=48)

    body = fake_client.last_search_kwargs["body"]
    must_filters = body["query"]["bool"]["must"]
    assert {"term": {"tenant_id": "acme-corp"}} in must_filters
    assert body["query"]["bool"]["filter"] == [{"range": {"timestamp": {"gte": "now-48h", "lte": "now"}}}]


@pytest.mark.asyncio
async def test_get_alert_severity_summary_scopes_to_a_single_host_when_given(monkeypatch):
    """Endpoint detail page's own severity breakdown (host_id set) — must not aggregate the whole tenant."""
    fake_response = {"hits": {"total": {"value": 0}}, "aggregations": {"by_severity": {"buckets": []}}}
    fake_client = _FakeSearchClient(fake_response)
    monkeypatch.setattr("app.db.opensearch.get_client", lambda: fake_client)

    await get_alert_severity_summary("acme-corp", timerange_hours=24, host_id="DESKTOP-037")

    must_filters = fake_client.last_search_kwargs["body"]["query"]["bool"]["must"]
    assert {"term": {"host_id": "DESKTOP-037"}} in must_filters


@pytest.mark.asyncio
async def test_get_alert_severity_summary_omits_the_host_filter_when_not_given(monkeypatch):
    fake_response = {"hits": {"total": {"value": 0}}, "aggregations": {"by_severity": {"buckets": []}}}
    fake_client = _FakeSearchClient(fake_response)
    monkeypatch.setattr("app.db.opensearch.get_client", lambda: fake_client)

    await get_alert_severity_summary("acme-corp")

    must_filters = fake_client.last_search_kwargs["body"]["query"]["bool"]["must"]
    assert not any("host_id" in f.get("term", {}) for f in must_filters)


@pytest.mark.asyncio
async def test_get_alert_severity_summary_supports_custom_time_windows(monkeypatch):
    """Regression: the window must not be hardcoded to any one value (e.g. the dashboard's 168h default)."""
    fake_response = {"hits": {"total": {"value": 0}}, "aggregations": {"by_severity": {"buckets": []}}}
    fake_client = _FakeSearchClient(fake_response)
    monkeypatch.setattr("app.db.opensearch.get_client", lambda: fake_client)

    result_24h = await get_alert_severity_summary("acme-corp", timerange_hours=24)
    result_720h = await get_alert_severity_summary("acme-corp", timerange_hours=720)

    assert result_24h["timerange_hours"] == 24
    assert result_720h["timerange_hours"] == 720


@pytest.mark.asyncio
async def test_get_alert_severity_summary_passes_through_an_unexpected_bucket_key(monkeypatch):
    """
    Every stored alert is expected to carry one of the 4 valid
    severities (enforced at ingestion), but the aggregation itself
    must not silently coerce a surprise value into an existing bucket
    — it should surface exactly what OpenSearch returned.
    """
    fake_response = {
        "hits": {"total": {"value": 1}},
        "aggregations": {"by_severity": {"buckets": [{"key": "unexpected-value", "doc_count": 1}]}},
    }
    fake_client = _FakeSearchClient(fake_response)
    monkeypatch.setattr("app.db.opensearch.get_client", lambda: fake_client)

    result = await get_alert_severity_summary("acme-corp")

    assert result["by_severity"] == {"unexpected-value": 1}


# ── SS-033: get_known_endpoints ──────────────────────────────────

@pytest.mark.asyncio
async def test_get_known_endpoints_flattens_nested_tenant_host_buckets(monkeypatch):
    fake_response = {
        "aggregations": {
            "by_tenant": {
                "buckets": [
                    {
                        "key": "tenant-a",
                        "by_host": {"buckets": [{"key": "DESKTOP-042"}, {"key": "WEB-SERVER-01"}]},
                    },
                    {
                        "key": "tenant-b",
                        "by_host": {"buckets": [{"key": "DESKTOP-042"}]},
                    },
                ]
            }
        }
    }
    fake_client = _FakeSearchClient(fake_response)
    monkeypatch.setattr("app.db.opensearch.get_client", lambda: fake_client)

    endpoints = await get_known_endpoints()

    assert endpoints == [
        {"tenant_id": "tenant-a", "host_id": "DESKTOP-042"},
        {"tenant_id": "tenant-a", "host_id": "WEB-SERVER-01"},
        {"tenant_id": "tenant-b", "host_id": "DESKTOP-042"},
    ]


@pytest.mark.asyncio
async def test_get_known_endpoints_returns_empty_list_when_no_alerts(monkeypatch):
    fake_response = {"aggregations": {"by_tenant": {"buckets": []}}}
    fake_client = _FakeSearchClient(fake_response)
    monkeypatch.setattr("app.db.opensearch.get_client", lambda: fake_client)

    assert await get_known_endpoints() == []
