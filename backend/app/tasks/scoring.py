"""
SafeSOC — Scheduled Risk Recalculation Task
Periodic Celery beat task (SS-033) that re-scores every known endpoint,
so SS-032's time-decay behavior actually manifests between alert-
ingestion events, not just at ingestion time. Runs on the interval
configured by settings.RISK_RECALC_INTERVAL_MINUTES (see
tasks/celery_app.py's beat_schedule).
"""

import asyncio
import uuid

from app.core.config import settings
from app.db.opensearch import get_known_endpoints, search_alerts
from app.db.postgresql import async_session_factory, engine
from app.services.risk_scoring import recalculate_endpoint_score
from app.tasks.celery_app import celery_app
from app.utils.logger import get_logger

logger = get_logger(__name__)


@celery_app.task(name="app.tasks.scoring.recalculate_all_risk_scores")
def recalculate_all_risk_scores() -> None:
    """Celery beat entrypoint: re-score every known endpoint."""
    asyncio.run(_recalculate_all_risk_scores_async())


async def _recalculate_all_risk_scores_async() -> None:
    # The SQLAlchemy engine (db/postgresql.py) is a process-wide singleton
    # shared by every Celery task this worker process runs (enrichment,
    # correlation, this one). asyncio.run() gives each task invocation its
    # own event loop, but asyncpg connections are bound to the loop that
    # created them — so a connection left in the pool by *any* earlier
    # task (this one's own previous run, or a different task type
    # entirely) is poisoned for this run's loop. Disposing before first
    # use, not just after, is what actually makes this reliable: it's not
    # enough to clean up after ourselves, because a worker can run other
    # DB-touching tasks in between (observed live: disposing only in a
    # trailing `finally` still failed on this task's second invocation,
    # since the pool had already been reused by another task by then).
    await engine.dispose()
    try:
        endpoints = await get_known_endpoints(timerange_hours=settings.RISK_RECALC_LOOKBACK_HOURS)
        if not endpoints:
            return

        async with async_session_factory() as db:
            for entry in endpoints:
                alerts_result = await search_alerts(
                    tenant_id=entry["tenant_id"],
                    host_id=entry["host_id"],
                    timerange_hours=settings.RISK_RECALC_LOOKBACK_HOURS,
                    size=500,
                )
                await recalculate_endpoint_score(
                    db, uuid.UUID(entry["tenant_id"]), entry["host_id"], alerts_result["alerts"]
                )

        logger.info("Recalculated risk scores", endpoint_count=len(endpoints))
    finally:
        # Leave the pool clean for whatever runs next on this worker too,
        # not just guard our own next run.
        await engine.dispose()
