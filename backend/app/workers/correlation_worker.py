"""
SafeSOC — Correlation Worker
Runs SS-028's pattern detectors against a host's sliding window after a
log is accepted by POST /api/v1/ingest, so attack chains are detected
within seconds of ingestion (SRS §3.3), not on a delay.
"""

import asyncio

from app.db.opensearch import get_alert_by_id
from app.services.correlation import add_event, evaluate_host
from app.tasks.celery_app import celery_app
from app.utils.logger import get_logger

logger = get_logger(__name__)


@celery_app.task(name="app.workers.correlation_worker.evaluate_correlation")
def evaluate_correlation(alert_id: str) -> None:
    """Celery entrypoint: add the alert to its host's window, then re-evaluate every pattern detector."""
    asyncio.run(_evaluate_correlation_async(alert_id))


async def _evaluate_correlation_async(alert_id: str) -> None:
    doc = await get_alert_by_id(alert_id)
    if doc is None:
        logger.warning("Correlation task could not find alert", alert_id=alert_id)
        return

    tenant_id = doc["tenant_id"]
    host_id = doc["host_id"]

    await add_event(
        tenant_id,
        host_id,
        {
            "alert_id": doc.get("alert_id"),
            "log_type": doc.get("log_type"),
            "action": doc.get("action"),
            "severity": doc.get("severity"),
            "destination_ip": doc.get("destination_ip"),
        },
    )

    chains = await evaluate_host(tenant_id, host_id)
    for chain in chains:
        logger.info(
            "Correlation chain detected",
            tenant_id=tenant_id,
            host_id=host_id,
            pattern=chain.pattern.value,
            confidence=round(chain.confidence, 2),
            alert_ids=list(chain.alert_ids),
            mitre_technique_ids=list(chain.mitre_technique_ids),
            mitre_tactic=chain.mitre_tactic,
        )
