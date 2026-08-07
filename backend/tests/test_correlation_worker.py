"""
SafeSOC — Correlation Worker Tests
"""

import uuid
from unittest.mock import AsyncMock, Mock

import pytest

from app.core.enums import CorrelationPattern
from app.models.incident import Incident, IncidentStatus
from app.services.correlation import DetectedChain
from app.tasks.celery_app import celery_app
from app.workers import correlation_worker


class _FakeSessionCM:
    async def __aenter__(self):
        return "fake-db-session"

    async def __aexit__(self, *args):
        return False


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
async def test_evaluate_correlation_async_creates_an_incident_and_logs_each_detected_chain(monkeypatch):
    tenant_id = uuid.uuid4()
    doc = {
        "alert_id": "abc-123",
        "tenant_id": str(tenant_id),
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
    incident = Incident(id=uuid.uuid4(), tenant_id=tenant_id, status=IncidentStatus.OPEN, alert_ids=["a1", "a2"])

    monkeypatch.setattr(correlation_worker, "get_alert_by_id", AsyncMock(return_value=doc))
    monkeypatch.setattr(correlation_worker, "add_event", AsyncMock())
    monkeypatch.setattr(correlation_worker, "evaluate_host", AsyncMock(return_value=[chain]))
    monkeypatch.setattr(correlation_worker, "async_session_factory", lambda: _FakeSessionCM())
    mock_create_or_merge = AsyncMock(return_value=incident)
    monkeypatch.setattr(correlation_worker, "create_or_merge_incident", mock_create_or_merge)

    logged = []
    monkeypatch.setattr(correlation_worker.logger, "info", lambda msg, **kw: logged.append((msg, kw)))

    await correlation_worker._evaluate_correlation_async("abc-123")

    mock_create_or_merge.assert_called_once_with("fake-db-session", tenant_id, "DESKTOP-042", chain)

    assert len(logged) == 1
    message, fields = logged[0]
    assert "chain" in message.lower()
    assert fields["pattern"] == "credential_brute_force"
    assert fields["alert_ids"] == ["a1", "a2"]
    assert fields["incident_id"] == str(incident.id)


@pytest.mark.asyncio
async def test_evaluate_correlation_async_notifies_for_each_detected_chain(monkeypatch):
    """SS-056 AC: a new attack chain triggers a notification."""
    tenant_id = uuid.uuid4()
    doc = {
        "alert_id": "abc-123",
        "tenant_id": str(tenant_id),
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
    incident = Incident(id=uuid.uuid4(), tenant_id=tenant_id, status=IncidentStatus.OPEN, alert_ids=["a1", "a2"])

    monkeypatch.setattr(correlation_worker, "get_alert_by_id", AsyncMock(return_value=doc))
    monkeypatch.setattr(correlation_worker, "add_event", AsyncMock())
    monkeypatch.setattr(correlation_worker, "evaluate_host", AsyncMock(return_value=[chain]))
    monkeypatch.setattr(correlation_worker, "async_session_factory", lambda: _FakeSessionCM())
    monkeypatch.setattr(correlation_worker, "create_or_merge_incident", AsyncMock(return_value=incident))
    mock_notify = Mock()
    monkeypatch.setattr(correlation_worker, "notify_attack_chain", mock_notify)

    await correlation_worker._evaluate_correlation_async("abc-123")

    mock_notify.assert_called_once_with("DESKTOP-042", chain, incident.id)


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
