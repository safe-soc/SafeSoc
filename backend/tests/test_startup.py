"""
SafeSOC — Startup Guard Tests (SS-067)
Covers the JWT_SECRET default-value guard in main.py's startup event.
"""

from unittest.mock import AsyncMock

import pytest

from app.core.config import settings
from app.main import DEFAULT_JWT_SECRET, startup


@pytest.fixture(autouse=True)
def _mock_ensure_ilm_policy(monkeypatch) -> AsyncMock:
    """Never attempt a real OpenSearch connection from the startup event."""
    mock = AsyncMock()
    monkeypatch.setattr("app.db.opensearch.ensure_ilm_policy", mock)
    return mock


@pytest.mark.asyncio
async def test_refuses_to_start_with_the_default_jwt_secret_in_production(monkeypatch):
    monkeypatch.setattr(settings, "JWT_SECRET", DEFAULT_JWT_SECRET)
    monkeypatch.setattr(settings, "ENV", "production")

    with pytest.raises(RuntimeError):
        await startup()


@pytest.mark.asyncio
async def test_starts_with_the_default_jwt_secret_outside_production(monkeypatch):
    monkeypatch.setattr(settings, "JWT_SECRET", DEFAULT_JWT_SECRET)
    monkeypatch.setattr(settings, "ENV", "development")

    await startup()  # should not raise


@pytest.mark.asyncio
async def test_starts_in_production_with_a_non_default_jwt_secret(monkeypatch):
    monkeypatch.setattr(settings, "JWT_SECRET", "a-real-randomly-generated-secret")
    monkeypatch.setattr(settings, "ENV", "production")

    await startup()  # should not raise
