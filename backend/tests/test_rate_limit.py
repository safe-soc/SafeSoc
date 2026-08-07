"""
SafeSOC — Rate Limiting Tests (SS-067)
"""

from unittest.mock import AsyncMock, Mock

import pytest

from app.core.exceptions import RateLimitExceededError
from app.services.rate_limit import enforce_rate_limit


def _fake_redis_client(incr_side_effect):
    client = Mock()
    client.incr = AsyncMock(side_effect=incr_side_effect)
    client.expire = AsyncMock()
    return client


@pytest.mark.asyncio
async def test_allows_requests_at_or_under_the_limit(monkeypatch):
    client = _fake_redis_client([1, 2, 5])
    monkeypatch.setattr("app.services.rate_limit.get_client", lambda: client)

    for _ in range(3):
        await enforce_rate_limit("key", max_attempts=5, window_seconds=60)  # should not raise


@pytest.mark.asyncio
async def test_sets_the_window_ttl_only_on_the_first_increment(monkeypatch):
    client = _fake_redis_client([1, 2, 3])
    monkeypatch.setattr("app.services.rate_limit.get_client", lambda: client)

    for _ in range(3):
        await enforce_rate_limit("key", max_attempts=5, window_seconds=60)

    client.expire.assert_called_once_with("key", 60)


@pytest.mark.asyncio
async def test_raises_once_the_limit_is_exceeded(monkeypatch):
    client = _fake_redis_client([6])
    monkeypatch.setattr("app.services.rate_limit.get_client", lambda: client)

    with pytest.raises(RateLimitExceededError):
        await enforce_rate_limit("key", max_attempts=5, window_seconds=60)


@pytest.mark.asyncio
async def test_fails_open_when_redis_is_unreachable(monkeypatch):
    client = Mock()
    client.incr = AsyncMock(side_effect=ConnectionError("no redis"))
    monkeypatch.setattr("app.services.rate_limit.get_client", lambda: client)

    await enforce_rate_limit("key", max_attempts=5, window_seconds=60)  # should not raise
