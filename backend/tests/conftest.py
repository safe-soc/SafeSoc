"""
SafeSOC — Shared Test Fixtures
Reusable pytest fixtures for the backend test suite.
"""

from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client() -> TestClient:
    """FastAPI TestClient wrapping the SafeSOC app, for HTTP-level endpoint tests."""
    return TestClient(app)


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
