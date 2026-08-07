"""
SafeSOC — Notification Worker Tests (SS-056)
"""

from unittest.mock import AsyncMock, Mock

import pytest

from app.tasks.celery_app import celery_app
from app.workers import notification_worker


def test_notify_if_critical_task_is_registered_with_celery():
    assert "app.workers.notification_worker.notify_if_critical" in celery_app.tasks


@pytest.mark.asyncio
async def test_notify_if_critical_async_notifies_when_the_alert_is_found(monkeypatch):
    doc = {"alert_id": "abc-123", "host_id": "DESKTOP-042", "severity": "critical"}
    monkeypatch.setattr(notification_worker, "get_alert_by_id", AsyncMock(return_value=doc))
    mock_notify = Mock(return_value=True)
    monkeypatch.setattr(notification_worker, "notify_critical_alert", mock_notify)

    await notification_worker._notify_if_critical_async("abc-123")

    mock_notify.assert_called_once_with(doc)


@pytest.mark.asyncio
async def test_notify_if_critical_async_no_ops_when_alert_not_found(monkeypatch):
    monkeypatch.setattr(notification_worker, "get_alert_by_id", AsyncMock(return_value=None))
    mock_notify = Mock()
    monkeypatch.setattr(notification_worker, "notify_critical_alert", mock_notify)

    await notification_worker._notify_if_critical_async("does-not-exist")  # must not raise

    mock_notify.assert_not_called()


@pytest.mark.asyncio
async def test_notify_if_critical_async_does_not_raise_when_notify_returns_false(monkeypatch):
    doc = {"alert_id": "abc-123", "host_id": "DESKTOP-042", "severity": "low"}
    monkeypatch.setattr(notification_worker, "get_alert_by_id", AsyncMock(return_value=doc))
    monkeypatch.setattr(notification_worker, "notify_critical_alert", Mock(return_value=False))

    await notification_worker._notify_if_critical_async("abc-123")  # must not raise


def test_notify_if_critical_runs_the_async_flow_via_asyncio_run(monkeypatch):
    calls = []

    async def _fake_async(alert_id):
        calls.append(alert_id)

    monkeypatch.setattr(notification_worker, "_notify_if_critical_async", _fake_async)

    notification_worker.notify_if_critical.run("xyz-789")

    assert calls == ["xyz-789"]
