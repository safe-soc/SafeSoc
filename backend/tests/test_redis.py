"""
SafeSOC — Redis Client Tests
"""

import pytest

from app.db.redis import check_connection


class _FakeClient:
    def __init__(self, should_raise: bool):
        self._should_raise = should_raise

    async def ping(self):
        if self._should_raise:
            raise ConnectionError("could not connect to redis")
        return True


@pytest.mark.asyncio
async def test_check_connection_true_when_ping_succeeds(monkeypatch):
    monkeypatch.setattr("app.db.redis.get_client", lambda: _FakeClient(should_raise=False))

    assert await check_connection() is True


@pytest.mark.asyncio
async def test_check_connection_false_when_ping_raises(monkeypatch):
    monkeypatch.setattr("app.db.redis.get_client", lambda: _FakeClient(should_raise=True))

    assert await check_connection() is False
