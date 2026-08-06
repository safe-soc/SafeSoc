"""
SafeSOC — Enrichment Celery Task Tests
"""

from unittest.mock import AsyncMock

import pytest

from app.tasks import enrichment as enrichment_task
from app.tasks.celery_app import celery_app


def test_enrich_alert_task_is_registered_with_celery():
    assert "app.tasks.enrichment.enrich_alert" in celery_app.tasks


class _FakeSessionCM:
    async def __aenter__(self):
        return "fake-db-session"

    async def __aexit__(self, *args):
        return False


@pytest.mark.asyncio
async def test_enrich_alert_async_fetches_and_enriches_the_alert(monkeypatch):
    doc = {
        "alert_id": "abc-123",
        "tenant_id": "acme-corp",
        "source": "synthetic",
        "log_type": "network",
        "timestamp": "2026-08-06T02:47:11Z",
        "host_id": "H1",
        "host_ip": "10.0.0.1",
        "action": "conn",
        "description": "test",
        "severity": "low",
        "source_ip": "45.33.32.156",
    }
    monkeypatch.setattr(enrichment_task, "get_alert_by_id", AsyncMock(return_value=doc))
    mock_enrich_log = AsyncMock()
    monkeypatch.setattr(enrichment_task, "enrich_log", mock_enrich_log)
    monkeypatch.setattr(enrichment_task, "async_session_factory", lambda: _FakeSessionCM())

    await enrichment_task._enrich_alert_async("abc-123")

    mock_enrich_log.assert_called_once()
    db_arg, log_arg = mock_enrich_log.call_args.args
    assert db_arg == "fake-db-session"
    assert log_arg.alert_id == "abc-123"
    assert log_arg.source_ip == "45.33.32.156"


@pytest.mark.asyncio
async def test_enrich_alert_async_no_ops_when_alert_not_found(monkeypatch):
    monkeypatch.setattr(enrichment_task, "get_alert_by_id", AsyncMock(return_value=None))
    mock_enrich_log = AsyncMock()
    monkeypatch.setattr(enrichment_task, "enrich_log", mock_enrich_log)

    await enrichment_task._enrich_alert_async("does-not-exist")  # must not raise

    mock_enrich_log.assert_not_called()


def test_enrich_alert_runs_the_async_flow_via_asyncio_run(monkeypatch):
    """The sync Celery entrypoint must actually drive _enrich_alert_async to completion."""
    calls = []

    async def _fake_async(alert_id):
        calls.append(alert_id)

    monkeypatch.setattr(enrichment_task, "_enrich_alert_async", _fake_async)

    enrichment_task.enrich_alert.run("xyz-789")

    assert calls == ["xyz-789"]
