"""
SafeSOC — Celery Application
Broker/result-backend wiring against Redis; task modules register against this app.
"""

from celery import Celery

from app.core.config import settings

celery_app = Celery(
    "safesoc",
    broker=settings.redis_url,
    backend=settings.redis_url,
)


@celery_app.task(name="app.tasks.celery_app.ping")
def ping() -> str:
    """Trivial task proving the broker/worker pipeline works end-to-end."""
    return "pong"
