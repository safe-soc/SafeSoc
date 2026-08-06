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
    # The worker process only runs `celery -A app.tasks.celery_app worker`,
    # so task modules beyond this one must be listed here explicitly to be
    # imported (and their @celery_app.task-decorated functions registered)
    # — otherwise a task is queueable from the producer side (which imports
    # it directly) but silently unknown to the worker.
    include=["app.tasks.enrichment"],
)

# A hung (not just refused) broker connection would silently defeat ADR-005's
# whole point — ingestion queuing a task must fail fast, not block for the OS's
# default TCP timeout or Celery's own connection-retry backoff, if Redis is
# slow or unreachable.
celery_app.conf.broker_connection_timeout = 2
celery_app.conf.broker_connection_retry = False
celery_app.conf.broker_connection_retry_on_startup = False
celery_app.conf.broker_connection_max_retries = 0
celery_app.conf.broker_transport_options = {"socket_connect_timeout": 2, "socket_timeout": 2}
celery_app.conf.result_backend_transport_options = {"socket_connect_timeout": 2, "socket_timeout": 2}


@celery_app.task(name="app.tasks.celery_app.ping")
def ping() -> str:
    """Trivial task proving the broker/worker pipeline works end-to-end."""
    return "pong"
