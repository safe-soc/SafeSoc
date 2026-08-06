"""
SafeSOC — Correlation Engine
Per-endpoint, per-tenant sliding-window event storage in Redis (SRS §3.3):
sorted sets keyed by tenant_id:host_id, queried by later pattern detectors.
"""

import json
import time
from typing import Any, Optional

from app.core.config import settings
from app.db.redis import get_client

# Namespaced to avoid colliding with other Redis usage on the same
# instance (e.g. Celery's own broker/result keys).
WINDOW_KEY_PREFIX = "correlation:window"


def _window_key(tenant_id: str, host_id: str) -> str:
    return f"{WINDOW_KEY_PREFIX}:{tenant_id}:{host_id}"


async def add_event(
    tenant_id: str,
    host_id: str,
    event: dict[str, Any],
    timestamp: Optional[float] = None,
) -> None:
    """
    Record an event in host_id's sliding window for tenant_id.

    `timestamp` (unix seconds) is the sorted-set score; defaults to now,
    but callers (tests) may backdate it directly instead of manipulating
    the real clock. The window key's Redis TTL is (re)set to
    CORRELATION_WINDOW_TTL on every write, so an idle host's window is
    cleaned up automatically once nothing has touched it for that long.
    """
    ts = timestamp if timestamp is not None else time.time()
    key = _window_key(tenant_id, host_id)
    member = json.dumps(event, sort_keys=True)

    client = get_client()
    await client.zadd(key, {member: ts})
    await client.expire(key, settings.CORRELATION_WINDOW_TTL)


async def get_events(
    tenant_id: str,
    host_id: str,
    window_minutes: int,
    *,
    now: Optional[float] = None,
) -> list[dict[str, Any]]:
    """
    Return host_id's events (tenant-scoped) from the last window_minutes,
    oldest first. Events outside the window are excluded by score
    regardless of whether Redis has physically expired the key yet, so
    "old entries don't come back" is deterministic and testable without
    waiting on real time.

    `now` (unix seconds) is injectable for tests; defaults to the real
    current time.
    """
    now = now if now is not None else time.time()
    floor = now - (window_minutes * 60)
    key = _window_key(tenant_id, host_id)

    client = get_client()
    members = await client.zrangebyscore(key, floor, now)
    return [json.loads(member) for member in members]
