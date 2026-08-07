"""
SafeSOC — Notification Worker
Celery entrypoint (SS-056) queued for every accepted alert
(services/ingestion.py:queue_post_ingest_tasks), same as enrichment
and correlation — never blocks the ingestion response (ADR-005).
Pushes an immediate Telegram notification (SS-055) for critical-
severity alerts; anything below critical is a no-op, decided inside
services.notifications.notify_critical_alert.

Attack-chain notifications (the AC's other trigger) aren't queued
through this worker: a DetectedChain isn't itself a persisted, re-
fetchable-by-ID record the way an alert is, so
app.workers.correlation_worker calls
services.notifications.notify_attack_chain directly instead, right
alongside its existing chain-detected log line.
"""

import asyncio

from app.db.opensearch import get_alert_by_id
from app.services.notifications import notify_critical_alert
from app.tasks.celery_app import celery_app
from app.utils.logger import get_logger

logger = get_logger(__name__)


@celery_app.task(name="app.workers.notification_worker.notify_if_critical")
def notify_if_critical(alert_id: str) -> None:
    """Celery entrypoint: fetch the alert by ID and notify if it's critical-severity."""
    asyncio.run(_notify_if_critical_async(alert_id))


async def _notify_if_critical_async(alert_id: str) -> None:
    doc = await get_alert_by_id(alert_id)
    if doc is None:
        logger.warning("Notification task could not find alert", alert_id=alert_id)
        return

    sent = notify_critical_alert(doc)
    if sent:
        logger.info("Sent critical alert notification", alert_id=alert_id, host_id=doc.get("host_id"))
