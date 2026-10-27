"""
SafeSOC — Enrichment Celery Task
Runs threat-intel enrichment (SS-025) asynchronously after a log is
accepted by POST /api/v1/ingest, so enrichment latency never blocks
the ingestion response (ADR-005, docs/decisions.md). Also scores the
alert's behavioral anomaly context (SS-050) and persists the result
(SS-102) — previously built and tested but never actually invoked
anywhere in the live pipeline.
"""

import asyncio

from app.db.opensearch import get_alert_by_id, update_alert_anomaly_score
from app.db.postgresql import worker_session_factory
from app.schemas.log import NormalizedLog
from app.services.anomaly import score_alert
from app.services.enrichment import enrich_log, refresh_ip
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
    async with worker_session_factory() as db:
        await enrich_log(db, log)

    await _score_anomaly(log)


@celery_app.task(name="app.tasks.enrichment.refresh_indicator")
def refresh_indicator(ip: str) -> None:
    """
    Celery entrypoint for an analyst-requested TI refresh
    (services/threat_intel_refresh.py). Runs here, not in the API
    process, because the provider clients block on rate limits.
    """
    asyncio.run(_refresh_indicator_async(ip))


async def _refresh_indicator_async(ip: str) -> None:
    try:
        async with worker_session_factory() as db:
            result = await refresh_ip(db, ip)
    except Exception as e:
        logger.error("Threat-intel refresh failed", ip=ip, error_type=type(e).__name__, error=str(e))
        return
    logger.info(
        "Threat-intel refresh completed", ip=ip, is_malicious=result.is_malicious,
        has_vt=result.vt is not None, has_abuse=result.abuse is not None,
    )


async def _score_anomaly(log: NormalizedLog) -> None:
    """
    Score this alert's behavioral context against the trained anomaly
    model (SS-050) and persist the result (SS-102), so it starts
    actually reaching what already reads it: risk_scoring.py's existing
    RISK_SCORE_ANOMALY_BONUS, and any MCP tool returning raw alert
    dicts (e.g. auth_failures, endpoint_snapshot) — both already look
    for anomaly_score on the alert document, they just never had one.
    No-ops if no model has been trained yet (score_alert returns None),
    same degrade-gracefully behavior as before this change. Scoring
    failures are caught and logged rather than raised, so a problem
    here never undoes the TI enrichment that already committed above.
    """
    try:
        result = await score_alert(str(log.tenant_id), log.host_id, log.timestamp)
    except Exception as e:
        logger.warning("Anomaly scoring failed", alert_id=log.alert_id, error_type=type(e).__name__, error=str(e))
        return

    if result is None:
        return

    await update_alert_anomaly_score(alert_id=log.alert_id, timestamp=log.timestamp, anomaly_score=result.score)
