"""
SafeSOC — Correlation Engine Tests
"""

import pytest

from app.core.config import settings
from app.services import correlation


class _FakeRedisClient:
    """
    Minimal in-memory sorted-set fake — enough to exercise correlation.py's
    real query/filter logic without a live Redis connection.
    """

    def __init__(self):
        self._zsets: dict[str, dict[str, float]] = {}
        self.expire_calls: list[tuple[str, int]] = []

    async def zadd(self, key, mapping):
        self._zsets.setdefault(key, {}).update(mapping)

    async def expire(self, key, ttl):
        self.expire_calls.append((key, ttl))

    async def zrangebyscore(self, key, min, max):
        members = self._zsets.get(key, {})
        return [
            member for member, score in sorted(members.items(), key=lambda kv: kv[1])
            if min <= score <= max
        ]


@pytest.fixture
def fake_redis(monkeypatch) -> _FakeRedisClient:
    client = _FakeRedisClient()
    monkeypatch.setattr(correlation, "get_client", lambda: client)
    return client


# ── SS-027: add + query a window ──────────────────────────────

@pytest.mark.asyncio
async def test_added_event_is_returned_by_get_events(fake_redis):
    now = 1_700_000_000.0
    await correlation.add_event("acme-corp", "DESKTOP-042", {"action": "failed_login"}, timestamp=now)

    events = await correlation.get_events("acme-corp", "DESKTOP-042", window_minutes=5, now=now)

    assert events == [{"action": "failed_login"}]


@pytest.mark.asyncio
async def test_get_events_returns_multiple_events_oldest_first(fake_redis):
    now = 1_700_000_000.0
    await correlation.add_event("acme-corp", "DESKTOP-042", {"seq": 2}, timestamp=now - 10)
    await correlation.add_event("acme-corp", "DESKTOP-042", {"seq": 1}, timestamp=now - 20)
    await correlation.add_event("acme-corp", "DESKTOP-042", {"seq": 3}, timestamp=now)

    events = await correlation.get_events("acme-corp", "DESKTOP-042", window_minutes=5, now=now)

    assert [e["seq"] for e in events] == [1, 2, 3]


@pytest.mark.asyncio
async def test_get_events_is_scoped_per_host(fake_redis):
    now = 1_700_000_000.0
    await correlation.add_event("acme-corp", "HOST-A", {"host": "a"}, timestamp=now)
    await correlation.add_event("acme-corp", "HOST-B", {"host": "b"}, timestamp=now)

    events = await correlation.get_events("acme-corp", "HOST-A", window_minutes=5, now=now)

    assert events == [{"host": "a"}]


@pytest.mark.asyncio
async def test_get_events_is_scoped_per_tenant(fake_redis):
    """Two tenants with the same host_id must not see each other's events — multi-tenancy isolation."""
    now = 1_700_000_000.0
    await correlation.add_event("tenant-a", "DESKTOP-042", {"tenant": "a"}, timestamp=now)
    await correlation.add_event("tenant-b", "DESKTOP-042", {"tenant": "b"}, timestamp=now)

    events = await correlation.get_events("tenant-a", "DESKTOP-042", window_minutes=5, now=now)

    assert events == [{"tenant": "a"}]


# ── SS-027: old entries don't come back — time-manipulated, no real wait ──

@pytest.mark.asyncio
async def test_get_events_excludes_events_older_than_the_window(fake_redis):
    now = 1_700_000_000.0
    two_hours_ago = now - (2 * 3600)
    await correlation.add_event("acme-corp", "DESKTOP-042", {"stale": True}, timestamp=two_hours_ago)

    events = await correlation.get_events("acme-corp", "DESKTOP-042", window_minutes=60, now=now)

    assert events == []


@pytest.mark.asyncio
async def test_get_events_includes_events_at_the_exact_window_boundary(fake_redis):
    now = 1_700_000_000.0
    exactly_at_boundary = now - (60 * 60)  # exactly 60 minutes ago
    await correlation.add_event("acme-corp", "DESKTOP-042", {"boundary": True}, timestamp=exactly_at_boundary)

    events = await correlation.get_events("acme-corp", "DESKTOP-042", window_minutes=60, now=now)

    assert events == [{"boundary": True}]


@pytest.mark.asyncio
async def test_get_events_defaults_to_the_current_time_when_now_is_omitted(fake_redis):
    await correlation.add_event("acme-corp", "DESKTOP-042", {"recent": True})

    events = await correlation.get_events("acme-corp", "DESKTOP-042", window_minutes=5)

    assert events == [{"recent": True}]


# ── SS-027: storage TTL (Redis-level expiry, from CORRELATION_WINDOW_TTL) ──

@pytest.mark.asyncio
async def test_add_event_sets_the_configured_ttl_on_the_window_key(fake_redis):
    await correlation.add_event("acme-corp", "DESKTOP-042", {"action": "failed_login"}, timestamp=1_700_000_000.0)

    assert fake_redis.expire_calls == [
        (correlation._window_key("acme-corp", "DESKTOP-042"), settings.CORRELATION_WINDOW_TTL)
    ]


def test_window_key_format_matches_the_documented_tenant_host_scheme():
    key = correlation._window_key("acme-corp", "DESKTOP-042")

    assert key.endswith("acme-corp:DESKTOP-042")
