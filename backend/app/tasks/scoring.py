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
from app.db.postgresql import async_session_factory
from app.services.risk_scoring import recalculate_endpoint_score
from app.tasks.celery_app import celery_app
from app.utils.logger import get_logger

logger = get_logger(__name__)


@celery_app.task(name="app.tasks.scoring.recalculate_all_risk_scores")
def recalculate_all_risk_scores() -> None:
    """Celery beat entrypoint: re-score every known endpoint."""
    asyncio.run(_recalculate_all_risk_scores_async())


async def _recalculate_all_risk_scores_async() -> None:
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
