"""
SafeSOC — Scheduled Risk Recalculation Task Tests
"""

import uuid
from unittest.mock import AsyncMock

import pytest

from app.tasks import scoring


class _FakeSessionCM:
    async def __aenter__(self):
        return "fake-db-session"

    async def __aexit__(self, *args):
        return False


@pytest.mark.asyncio
async def test_recalculates_score_for_every_known_endpoint(monkeypatch):
    tenant_a, tenant_b = str(uuid.uuid4()), str(uuid.uuid4())
    endpoints = [
        {"tenant_id": tenant_a, "host_id": "DESKTOP-042"},
        {"tenant_id": tenant_b, "host_id": "WEB-SERVER-01"},
    ]
    monkeypatch.setattr(scoring, "get_known_endpoints", AsyncMock(return_value=endpoints))
    mock_search_alerts = AsyncMock(return_value={"alerts": ["fake-alert"]})
    monkeypatch.setattr(scoring, "search_alerts", mock_search_alerts)
    monkeypatch.setattr(scoring, "worker_session_factory", lambda: _FakeSessionCM())
    mock_recalculate = AsyncMock()
    monkeypatch.setattr(scoring, "recalculate_endpoint_score", mock_recalculate)

    await scoring._recalculate_all_risk_scores_async()

    assert mock_recalculate.call_count == 2
    mock_search_alerts.assert_any_call(tenant_id=tenant_a, host_id="DESKTOP-042", timerange_hours=24, size=500)
    mock_search_alerts.assert_any_call(tenant_id=tenant_b, host_id="WEB-SERVER-01", timerange_hours=24, size=500)
    mock_recalculate.assert_any_call("fake-db-session", uuid.UUID(tenant_a), "DESKTOP-042", ["fake-alert"])


@pytest.mark.asyncio
async def test_no_ops_when_there_are_no_known_endpoints(monkeypatch):
    monkeypatch.setattr(scoring, "get_known_endpoints", AsyncMock(return_value=[]))
    mock_search_alerts = AsyncMock()
    monkeypatch.setattr(scoring, "search_alerts", mock_search_alerts)
    mock_recalculate = AsyncMock()
    monkeypatch.setattr(scoring, "recalculate_endpoint_score", mock_recalculate)

    await scoring._recalculate_all_risk_scores_async()  # must not raise

    mock_search_alerts.assert_not_called()
    mock_recalculate.assert_not_called()


@pytest.mark.asyncio
async def test_uses_the_nullpool_worker_session_factory(monkeypatch):
    """
    Replaces the old dispose-before-and-after regression test. That
    existed because the shared pooled engine handed this task
    connections belonging to a previous task's (now closed) event loop.
    The task now draws from worker_session_factory, whose NullPool
    keeps nothing between checkouts, so there is no pool left to
    dispose and no stale connection to inherit — see
    tests/test_worker_db_lifecycle.py for the behavioural proof.
    """
    monkeypatch.setattr(scoring, "get_known_endpoints", AsyncMock(return_value=[{"tenant_id": str(uuid.uuid4()), "host_id": "H1"}]))
    monkeypatch.setattr(scoring, "search_alerts", AsyncMock(return_value={"alerts": []}))
    monkeypatch.setattr(scoring, "recalculate_endpoint_score", AsyncMock())
    used = []
    monkeypatch.setattr(scoring, "worker_session_factory", lambda: used.append(1) or _FakeSessionCM())

    await scoring._recalculate_all_risk_scores_async()

    assert used, "the task must obtain its session from the worker factory"


def test_recalculate_all_risk_scores_runs_the_async_flow_via_asyncio_run(monkeypatch):
    calls = []

    async def _fake_async():
        calls.append(True)

    monkeypatch.setattr(scoring, "_recalculate_all_risk_scores_async", _fake_async)

    scoring.recalculate_all_risk_scores.run()

    assert calls == [True]
