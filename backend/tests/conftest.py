"""
SafeSOC — Shared Test Fixtures
Reusable pytest fixtures for the backend test suite.
"""

import uuid
from typing import Optional
from unittest.mock import AsyncMock, Mock

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.enums import UserRole
from app.core.security import create_access_token
from app.main import app
from app.tasks.enrichment import enrich_alert
from app.workers.correlation_worker import evaluate_correlation
from app.workers.notification_worker import notify_if_critical


@pytest.fixture(autouse=True)
def _pinned_settings(monkeypatch) -> None:
    """
    Pin the settings the suite's expectations are written against to
    their code defaults, for every test.

    docker-compose.yml loads the root .env into the backend container
    (so one file configures backend/worker/beat — see
    docs/deployment.md), which means `docker compose exec backend
    pytest` inherits the developer's REAL configuration. With
    LLM_PROVIDER=groq and live provider keys in .env, 31 tests across
    test_investigate_router.py, test_incident_narrative.py,
    test_investigation_session.py and test_incidents_router.py failed
    inside Docker while passing locally: they assert against the
    default provider (ollama) and the unconfigured-key behavior, and
    they monkeypatch `ollama.generate` — which a groq-configured run
    never calls.

    Pinned here rather than passed as `-e` overrides on the command
    line, so the suite is hermetic wherever it runs. A test that needs
    a specific value still sets it itself: monkeypatch applies these
    first (autouse fixtures run before the test body) and the test's
    own later monkeypatch.setattr wins.
    """
    for name, value in (
        ("LLM_PROVIDER", "ollama"),
        ("GROQ_API_KEY", ""),
        ("VT_API_KEY", ""),
        ("ABUSEIPDB_API_KEY", ""),
        ("TELEGRAM_BOT_TOKEN", ""),
        ("TELEGRAM_CHAT_ID", ""),
    ):
        monkeypatch.setattr(settings, name, value)


@pytest.fixture(autouse=True)
def _no_outbound_http(monkeypatch) -> None:
    """
    No test may make a real network call to Groq, VirusTotal,
    AbuseIPDB, Telegram or Ollama. All five clients (app/clients/*.py)
    use `requests`, so blocking at the transport adapter catches every
    call that isn't mocked — including one a future test forgets to
    mock, which would otherwise spend a real API quota or hang on a
    timeout inside a container that does have keys and egress.

    Deliberately scoped to `requests` rather than sockets in general:
    the real-Postgres integration tests
    (test_enrichment_transaction_boundary.py) need their database
    connection, and opensearch-py/redis don't go through requests.
    Tests that replace `module.requests.post` with a Mock bypass this
    entirely, which is exactly how the client tests are written.
    """
    def _blocked(*args, **kwargs):
        raise RuntimeError(
            "Outbound HTTP is blocked in tests (tests/conftest.py::_no_outbound_http). "
            "Mock the client's requests.post/get instead of calling a real provider."
        )

    monkeypatch.setattr("requests.adapters.HTTPAdapter.send", _blocked)


@pytest.fixture(autouse=True)
def _mock_incident_summary_lookup(monkeypatch) -> AsyncMock:
    """
    Every incident response now carries hosts/severity derived from its
    linked alerts (services/incident_summary.py), which means one
    OpenSearch lookup per incident request. opensearch-py doesn't go
    through `requests`, so _no_outbound_http doesn't catch it: unmocked,
    every test touching an incident endpoint would query whatever
    OpenSearch answers on localhost:9200 (a developer's live stack) or
    wait on a connection failure in CI. Defaults to "no alerts resolve";
    tests of the summary itself override this with their own alerts.
    """
    mock = AsyncMock(return_value=[])
    monkeypatch.setattr("app.services.incident_summary.get_alerts_by_ids", mock)
    return mock


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
    def _make(tenant_id: Optional[uuid.UUID] = None, role: UserRole = UserRole.ANALYST, user_id: Optional[uuid.UUID] = None) -> dict:
        token = create_access_token(tenant_id or uuid.uuid4(), user_id or uuid.uuid4(), role)
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
