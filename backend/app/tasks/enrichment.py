"""
SafeSOC — Enrichment Celery Task
Runs threat-intel enrichment (SS-025) asynchronously after a log is
accepted by POST /api/v1/ingest, so enrichment latency never blocks
the ingestion response (ADR-005, docs/decisions.md).
"""

import asyncio

from app.db.opensearch import get_alert_by_id
from app.db.postgresql import async_session_factory
from app.schemas.log import NormalizedLog
from app.services.enrichment import enrich_log
from app.tasks.celery_app import celery_app
from app.utils.logger import get_logger

logger = get_logger(__name__)


@celery_app.task(name="app.tasks.enrichment.enrich_alert")
def enrich_alert(alert_id: str) -> None:
    """Celery entrypoint: fetch the alert by ID and run enrichment against it."""
    asyncio.run(_enrich_alert_async(alert_id))


async def _enrich_alert_async(alert_id: str) -> None:
    doc = await get_alert_by_id(alert_id)
    if doc is None:
        logger.warning("Enrichment task could not find alert", alert_id=alert_id)
        return

    log = NormalizedLog(**doc)
    async with async_session_factory() as db:
        await enrich_log(db, log)
