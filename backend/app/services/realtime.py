"""
SafeSOC — Real-Time Event Publishing (SS-063)
Publishes dashboard-relevant events (new critical alert, chain
detected/incident created) to a per-tenant Redis pub/sub channel.
Redis is already this stack's cross-process bus (Celery broker,
correlation sliding windows) — reused here rather than adding a new
one, since publishers run in different processes than the FastAPI
process serving the WebSocket connection (routers/ws.py): ingestion
publishes from the API process itself, but chain detection runs in a
Celery worker process, which has no direct handle on that process's
open WebSocket connections.
"""

import json
from typing import Any

from app.db.redis import get_client

CHANNEL_PREFIX = "realtime"


def channel_name(tenant_id: str) -> str:
    """Shared by routers/ws.py, which subscribes to the same channel this module publishes to."""
    return f"{CHANNEL_PREFIX}:{tenant_id}"


async def publish_event(tenant_id: str, event_type: str, payload: dict[str, Any]) -> None:
    """
    Publish a real-time event for tenant_id's connected dashboard
    clients (routers/ws.py). A no-op from the caller's perspective if
    nothing is currently subscribed — pub/sub messages with no
    listener are simply dropped, matching the "fire and forget,
    dashboard-only" nature of this feature (never raises into the
    ingestion/correlation path that triggered it).
    """
    client = get_client()
    message = json.dumps({"type": event_type, **payload})
    await client.publish(channel_name(tenant_id), message)
