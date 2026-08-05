"""
SafeSOC — PostgreSQL Client Tests
"""

import pytest

from app.db.postgresql import check_connection


class _FakeConnection:
    async def execute(self, *args, **kwargs):
        return None


class _FakeConnectCM:
    """Fake async context manager standing in for engine.connect()."""

    def __init__(self, should_raise: bool):
        self._should_raise = should_raise

    async def __aenter__(self):
        if self._should_raise:
            raise ConnectionError("could not connect to server")
        return _FakeConnection()

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakeEngine:
    def __init__(self, should_raise: bool):
        self._should_raise = should_raise

    def connect(self):
        return _FakeConnectCM(self._should_raise)


@pytest.mark.asyncio
async def test_check_connection_true_when_query_succeeds(monkeypatch):
    monkeypatch.setattr("app.db.postgresql.engine", _FakeEngine(should_raise=False))

    assert await check_connection() is True


@pytest.mark.asyncio
async def test_check_connection_false_when_connect_raises(monkeypatch):
    monkeypatch.setattr("app.db.postgresql.engine", _FakeEngine(should_raise=True))

    assert await check_connection() is False
