"""
SafeSOC — Celery Application
Broker/result-backend wiring against Redis; task modules register against this app.
"""

from celery import Celery
from celery.schedules import crontab

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
    include=[
        "app.tasks.enrichment",
        "app.tasks.scoring",
        "app.tasks.reporting",
        "app.workers.correlation_worker",
        "app.workers.notification_worker",
    ],
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

# Periodic risk recalculation (SS-033) — requires a `celery beat` process
# running alongside the worker (docker-compose.yml's `beat` service) to
# actually dispatch this on schedule; the worker process alone only
# executes tasks, it doesn't schedule them.
celery_app.conf.beat_schedule = {
    "recalculate-risk-scores": {
        "task": "app.tasks.scoring.recalculate_all_risk_scores",
        "schedule": settings.RISK_RECALC_INTERVAL_MINUTES * 60,
    },
    # Weekly report digest (SS-053) — a fixed day-of-week/hour-of-day, not
    # a simple interval, so this uses a crontab schedule rather than the
    # plain-seconds schedule above.
    #
    # settings.REPORT_SCHEDULE_DAY uses Python's datetime.weekday()
    # convention (0=Monday..6=Sunday — see core/config.py's own comment),
    # but Celery's crontab day_of_week uses cron's convention (0=Sunday..
    # 6=Saturday) — (day + 1) % 7 converts between them. Verified live:
    # without this conversion, the documented default (0, "Monday")
    # actually scheduled for Sunday.
    "generate-tenant-reports": {
        "task": "app.tasks.reporting.generate_all_tenant_reports",
        "schedule": crontab(hour=settings.REPORT_SCHEDULE_HOUR, day_of_week=(settings.REPORT_SCHEDULE_DAY + 1) % 7),
    },
}


@celery_app.task(name="app.tasks.celery_app.ping")
def ping() -> str:
    """Trivial task proving the broker/worker pipeline works end-to-end."""
    return "pong"
