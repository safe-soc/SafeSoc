"""
SafeSOC — Rate Limiting
Redis-backed fixed-window request counters (SS-067), applied to the
auth endpoints to slow down credential brute-forcing and mass
automated registration.
"""

from app.core.exceptions import RateLimitExceededError
from app.db.redis import get_client
from app.utils.logger import get_logger

logger = get_logger(__name__)


async def enforce_rate_limit(key: str, *, max_attempts: int, window_seconds: int) -> None:
    """
    Increment a fixed-window counter for `key`, raising
    RateLimitExceededError once it exceeds max_attempts within
    window_seconds. The window's TTL is set only on the first increment
    (mirrors CORRELATION_WINDOW_TTL's refresh-on-first-write pattern in
    services/correlation.py), so it resets window_seconds after the
    first attempt in a fresh window rather than sliding on every call.

    Fails open (allows the request through) if Redis itself is
    unreachable — an outage in the rate-limit backing store should
    degrade to "unprotected" rather than "auth endpoints down", since
    the latter is a worse availability failure than the brute-force
    risk this guards against.
    """
    try:
        client = get_client()
        count = await client.incr(key)
        if count == 1:
            await client.expire(key, window_seconds)
    except Exception as e:
        logger.warning("Rate limiter unavailable, allowing request", key=key, error=str(e))
        return

    if count > max_attempts:
        raise RateLimitExceededError()
