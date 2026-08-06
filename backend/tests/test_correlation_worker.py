"""
SafeSOC — Correlation Worker Tests
"""

from unittest.mock import AsyncMock

import pytest

from app.core.enums import CorrelationPattern
from app.services.correlation import DetectedChain
from app.tasks.celery_app import celery_app
from app.workers import correlation_worker


def test_evaluate_correlation_task_is_registered_with_celery():
    assert "app.workers.correlation_worker.evaluate_correlation" in celery_app.tasks


@pytest.mark.asyncio
async def test_evaluate_correlation_async_adds_the_event_then_evaluates_the_window(monkeypatch):
    doc = {
        "alert_id": "abc-123",
        "tenant_id": "acme-corp",
        "host_id": "DESKTOP-042",
        "log_type": "authentication",
        "action": "failed_login",
        "severity": "low",
        "destination_ip": None,
    }
    monkeypatch.setattr(correlation_worker, "get_alert_by_id", AsyncMock(return_value=doc))
    mock_add_event = AsyncMock()
    monkeypatch.setattr(correlation_worker, "add_event", mock_add_event)
    mock_evaluate_host = AsyncMock(return_value=[])
    monkeypatch.setattr(correlation_worker, "evaluate_host", mock_evaluate_host)

    await correlation_worker._evaluate_correlation_async("abc-123")

    mock_add_event.assert_called_once()
    tenant_arg, host_arg, event_arg = mock_add_event.call_args.args
    assert tenant_arg == "acme-corp"
    assert host_arg == "DESKTOP-042"
    assert event_arg["alert_id"] == "abc-123"
    assert event_arg["action"] == "failed_login"

    mock_evaluate_host.assert_called_once_with("acme-corp", "DESKTOP-042")


@pytest.mark.asyncio
async def test_evaluate_correlation_async_logs_each_detected_chain(monkeypatch):
    doc = {
        "alert_id": "abc-123",
        "tenant_id": "acme-corp",
        "host_id": "DESKTOP-042",
        "log_type": "authentication",
        "action": "failed_login",
        "severity": "low",
    }
    chain = DetectedChain(
        pattern=CorrelationPattern.CREDENTIAL_BRUTE_FORCE,
        confidence=0.8,
        alert_ids=("a1", "a2"),
        mitre_technique_ids=("T1110",),
        mitre_tactic="Credential Access",
    )
    monkeypatch.setattr(correlation_worker, "get_alert_by_id", AsyncMock(return_value=doc))
    monkeypatch.setattr(correlation_worker, "add_event", AsyncMock())
    monkeypatch.setattr(correlation_worker, "evaluate_host", AsyncMock(return_value=[chain]))

    logged = []
    monkeypatch.setattr(correlation_worker.logger, "info", lambda msg, **kw: logged.append((msg, kw)))

    await correlation_worker._evaluate_correlation_async("abc-123")

    assert len(logged) == 1
    message, fields = logged[0]
    assert "chain" in message.lower()
    assert fields["pattern"] == "credential_brute_force"
    assert fields["alert_ids"] == ["a1", "a2"]


@pytest.mark.asyncio
async def test_evaluate_correlation_async_no_ops_when_alert_not_found(monkeypatch):
    monkeypatch.setattr(correlation_worker, "get_alert_by_id", AsyncMock(return_value=None))
    mock_add_event = AsyncMock()
    mock_evaluate_host = AsyncMock()
    monkeypatch.setattr(correlation_worker, "add_event", mock_add_event)
    monkeypatch.setattr(correlation_worker, "evaluate_host", mock_evaluate_host)

    await correlation_worker._evaluate_correlation_async("does-not-exist")  # must not raise

    mock_add_event.assert_not_called()
    mock_evaluate_host.assert_not_called()


def test_evaluate_correlation_runs_the_async_flow_via_asyncio_run(monkeypatch):
    """The sync Celery entrypoint must actually drive _evaluate_correlation_async to completion."""
    calls = []

    async def _fake_async(alert_id):
        calls.append(alert_id)

    monkeypatch.setattr(correlation_worker, "_evaluate_correlation_async", _fake_async)

    correlation_worker.evaluate_correlation.run("xyz-789")

    assert calls == ["xyz-789"]
