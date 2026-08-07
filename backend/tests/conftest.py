"""
SafeSOC — Shared Test Fixtures
Reusable pytest fixtures for the backend test suite.
"""

import uuid
from typing import Optional
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi.testclient import TestClient

from app.core.enums import UserRole
from app.core.security import create_access_token
from app.main import app
from app.tasks.enrichment import enrich_alert
from app.workers.correlation_worker import evaluate_correlation
from app.workers.notification_worker import notify_if_critical


@pytest.fixture
def client() -> TestClient:
    """FastAPI TestClient wrapping the SafeSOC app, for HTTP-level endpoint tests."""
    return TestClient(app)


@pytest.fixture(autouse=True)
def _mock_enrichment_queueing(monkeypatch) -> Mock:
    """
    Never attempt a real Celery/Redis broker connection during tests.
    POST /api/v1/ingest queues enrichment via BackgroundTasks (SS-026),
    and TestClient runs background tasks synchronously as part of the
    request — an unmocked real .delay() would try (and, with no broker
    reachable, hang/fail) on every test that accepts a log.
    """
    mock = Mock()
    monkeypatch.setattr(enrich_alert, "delay", mock)
    return mock


@pytest.fixture(autouse=True)
def _mock_correlation_queueing(monkeypatch) -> Mock:
    """
    Same rationale as _mock_enrichment_queueing, for the second Celery
    task POST /api/v1/ingest queues per accepted log (SS-030).
    """
    mock = Mock()
    monkeypatch.setattr(evaluate_correlation, "delay", mock)
    return mock


@pytest.fixture(autouse=True)
def _mock_notification_queueing(monkeypatch) -> Mock:
    """
    Same rationale as _mock_enrichment_queueing, for the third Celery
    task POST /api/v1/ingest queues per accepted log (SS-056).
    """
    mock = Mock()
    monkeypatch.setattr(notify_if_critical, "delay", mock)
    return mock


@pytest.fixture(autouse=True)
def _mock_rate_limit(monkeypatch) -> AsyncMock:
    """
    Never attempt a real Redis connection during tests. SS-067's login/
    register rate limiting (services/rate_limit.py) hits Redis directly
    in-request; tests that want to exercise the limiter's own logic
    (test_rate_limit.py) or the 429 response it produces override this
    mock explicitly instead of relying on a live Redis.
    """
    mock = AsyncMock()
    monkeypatch.setattr("app.routers.v1.auth.enforce_rate_limit", mock)
    return mock


@pytest.fixture(autouse=True)
def _mock_realtime_publish(monkeypatch) -> AsyncMock:
    """
    Never attempt a real Redis connection during tests. Unlike the
    three fixtures above, this isn't a queued Celery task — SS-063's
    live dashboard push is awaited directly in-request (by design, for
    "few seconds" latency) whenever a batch contains a critical-severity
    alert, and services/incidents.py's chain-detection path calls it
    directly too.
    """
    mock = AsyncMock()
    monkeypatch.setattr("app.services.ingestion.publish_event", mock)
    monkeypatch.setattr("app.workers.correlation_worker.publish_event", mock)
    return mock


@pytest.fixture
def make_auth_headers():
    """Factory returning an Authorization: Bearer <JWT> header dict for a real, valid token (SS-013/015)."""
    def _make(tenant_id: Optional[uuid.UUID] = None, role: UserRole = UserRole.ANALYST) -> dict:
        token = create_access_token(tenant_id or uuid.uuid4(), uuid.uuid4(), role)
        return {"Authorization": f"Bearer {token}"}
    return _make


@pytest.fixture
def auth_headers(make_auth_headers) -> dict:
    """A valid Authorization header for an arbitrary, freshly-minted tenant — for tests that just need *some* authenticated caller."""
    return make_auth_headers()


@pytest.fixture
def base_log_fields() -> dict:
    """Minimal set of required NormalizedLog fields, excluding tenant_id/source (which the ingestion service injects itself)."""
    return {
        "log_type": "authentication",
        "timestamp": "2026-08-05T02:47:11Z",
        "host_id": "DESKTOP-042",
        "host_ip": "192.168.1.42",
        "action": "failed_login",
        "description": "Failed SSH authentication attempt",
        "severity": "low",
    }


@pytest.fixture
def mock_bulk_index_logs(monkeypatch) -> AsyncMock:
    """Replaces the real OpenSearch bulk-write call with an in-memory async mock, so ingestion tests never need a live OpenSearch instance."""
    mock = AsyncMock(return_value=0)
    monkeypatch.setattr("app.services.ingestion.bulk_index_logs", mock)
    return mock


@pytest.fixture
def mock_opensearch_unreachable(monkeypatch) -> AsyncMock:
    """Forces the health endpoint's OpenSearch check to report unreachable, simulating a down/unreachable cluster without needing one."""
    mock = AsyncMock(return_value=False)
    monkeypatch.setattr("app.routers.health.check_opensearch", mock)
    return mock
