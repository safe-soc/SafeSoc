"""
SafeSOC — Health Check Endpoint
Returns status of all connected services.
"""

from fastapi import APIRouter

from app.db.opensearch import check_connection as check_opensearch
from app.db.postgresql import check_connection as check_postgres
from app.db.redis import check_connection as check_redis

router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check():
    """Check connectivity to all dependent services."""
    opensearch_ok = await check_opensearch()
    postgres_ok = await check_postgres()
    redis_ok = await check_redis()

    checks = {
        "opensearch": "connected" if opensearch_ok else "unavailable",
        "postgresql": "connected" if postgres_ok else "unavailable",
        "redis": "connected" if redis_ok else "unavailable",
    }

    all_healthy = all(v == "connected" for v in checks.values())

    return {
        "status": "healthy" if all_healthy else "degraded",
        "version": "1.0.0",
        "checks": checks,
    }