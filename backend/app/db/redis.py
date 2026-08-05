"""
SafeSOC — Redis Client
Async client factory and connectivity check.
"""

import redis.asyncio as redis

from app.core.config import settings


def get_client() -> redis.Redis:
    """Create and return an async Redis client instance."""
    return redis.from_url(settings.redis_url)


async def check_connection() -> bool:
    """Check if Redis is reachable. Returns True if healthy."""
    try:
        client = get_client()
        return await client.ping()
    except Exception:
        return False
