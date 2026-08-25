"""
SafeSOC — Enrichment Celery Task Tests
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from app.services.anomaly import AnomalyResult
from app.tasks import enrichment as enrichment_task
from app.tasks.celery_app import celery_app


def test_enrich_alert_task_is_registered_with_celery():
    assert "app.tasks.enrichment.enrich_alert" in celery_app.tasks


class _FakeSessionCM:
    async def __aenter__(self):
        return "fake-db-session"

    async def __aexit__(self, *args):
        return False


_DOC = {
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


@pytest.fixture(autouse=True)
def _mock_anomaly_scoring(monkeypatch):
    """
    Every test in this file drives _enrich_alert_async(), which now also
    calls score_alert()/update_alert_anomaly_score() (SS-102) — default
    to "no trained model" (score_alert returns None, matching its own
    documented degrade-gracefully behavior) so existing TI-enrichment
    tests are unaffected; tests below override this explicitly.
    """
    monkeypatch.setattr(enrichment_task, "score_alert", AsyncMock(return_value=None))
    monkeypatch.setattr(enrichment_task, "update_alert_anomaly_score", AsyncMock())


@pytest.mark.asyncio
async def test_enrich_alert_async_fetches_and_enriches_the_alert(monkeypatch):
    monkeypatch.setattr(enrichment_task, "get_alert_by_id", AsyncMock(return_value=_DOC))
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


# ── SS-102: anomaly scoring wired into the enrichment task ────────

@pytest.mark.asyncio
async def test_enrich_alert_async_persists_a_real_anomaly_score(monkeypatch):
    monkeypatch.setattr(enrichment_task, "get_alert_by_id", AsyncMock(return_value=_DOC))
    monkeypatch.setattr(enrichment_task, "enrich_log", AsyncMock())
    monkeypatch.setattr(enrichment_task, "async_session_factory", lambda: _FakeSessionCM())
    mock_score_alert = AsyncMock(return_value=AnomalyResult(score=0.91, is_anomalous=True))
    monkeypatch.setattr(enrichment_task, "score_alert", mock_score_alert)
    mock_update = AsyncMock()
    monkeypatch.setattr(enrichment_task, "update_alert_anomaly_score", mock_update)

    await enrichment_task._enrich_alert_async("abc-123")

    mock_score_alert.assert_called_once_with("acme-corp", "H1", datetime(2026, 8, 6, 2, 47, 11, tzinfo=timezone.utc))
    mock_update.assert_called_once_with(
        alert_id="abc-123", timestamp=datetime(2026, 8, 6, 2, 47, 11, tzinfo=timezone.utc), anomaly_score=0.91
    )


@pytest.mark.asyncio
async def test_enrich_alert_async_does_not_persist_when_no_model_is_trained(monkeypatch):
    """score_alert() returning None (no trained model yet) is the existing, documented degrade-gracefully case."""
    monkeypatch.setattr(enrichment_task, "get_alert_by_id", AsyncMock(return_value=_DOC))
    monkeypatch.setattr(enrichment_task, "enrich_log", AsyncMock())
    monkeypatch.setattr(enrichment_task, "async_session_factory", lambda: _FakeSessionCM())
    monkeypatch.setattr(enrichment_task, "score_alert", AsyncMock(return_value=None))
    mock_update = AsyncMock()
    monkeypatch.setattr(enrichment_task, "update_alert_anomaly_score", mock_update)

    await enrichment_task._enrich_alert_async("abc-123")

    mock_update.assert_not_called()


@pytest.mark.asyncio
async def test_enrich_alert_async_survives_an_anomaly_scoring_failure(monkeypatch):
    """A scoring exception must not undo/prevent the TI enrichment that already committed, nor raise out of the task."""
    monkeypatch.setattr(enrichment_task, "get_alert_by_id", AsyncMock(return_value=_DOC))
    mock_enrich_log = AsyncMock()
    monkeypatch.setattr(enrichment_task, "enrich_log", mock_enrich_log)
    monkeypatch.setattr(enrichment_task, "async_session_factory", lambda: _FakeSessionCM())
    monkeypatch.setattr(enrichment_task, "score_alert", AsyncMock(side_effect=RuntimeError("redis unreachable")))
    mock_update = AsyncMock()
    monkeypatch.setattr(enrichment_task, "update_alert_anomaly_score", mock_update)

    await enrichment_task._enrich_alert_async("abc-123")  # must not raise

    mock_enrich_log.assert_called_once()  # TI enrichment still ran
    mock_update.assert_not_called()


@pytest.mark.asyncio
async def test_enrich_alert_async_scores_anomaly_per_tenant(monkeypatch):
    """Tenant isolation: score_alert() must be called with this alert's own tenant_id, not a global/shared scope."""
    other_doc = {**_DOC, "alert_id": "xyz-999", "tenant_id": "other-tenant", "host_id": "H2"}
    monkeypatch.setattr(enrichment_task, "get_alert_by_id", AsyncMock(return_value=other_doc))
    monkeypatch.setattr(enrichment_task, "enrich_log", AsyncMock())
    monkeypatch.setattr(enrichment_task, "async_session_factory", lambda: _FakeSessionCM())
    mock_score_alert = AsyncMock(return_value=None)
    monkeypatch.setattr(enrichment_task, "score_alert", mock_score_alert)

    await enrichment_task._enrich_alert_async("xyz-999")

    tenant_arg, host_arg, _ = mock_score_alert.call_args.args
    assert tenant_arg == "other-tenant"
    assert host_arg == "H2"


def test_enrich_alert_runs_the_async_flow_via_asyncio_run(monkeypatch):
    """The sync Celery entrypoint must actually drive _enrich_alert_async to completion."""
    calls = []

    async def _fake_async(alert_id):
        calls.append(alert_id)

    monkeypatch.setattr(enrichment_task, "_enrich_alert_async", _fake_async)

    enrichment_task.enrich_alert.run("xyz-789")

    assert calls == ["xyz-789"]
