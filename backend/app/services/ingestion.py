"""
SafeSOC — Ingestion Service
Dispatches raw, source-specific payloads through the matching adapter,
validates the result against NormalizedLog schema, and writes to OpenSearch.
"""

import asyncio
from typing import Callable, Optional

from fastapi import BackgroundTasks
from pydantic import ValidationError

from app.adapters import cloudlens, cloudtrail, guardduty, wazuh
from app.core.enums import LogSource
from app.core.exceptions import IngestionError
from app.db.opensearch import bulk_index_logs
from app.schemas.log import NormalizedLog
from app.tasks.enrichment import enrich_alert
from app.utils.logger import get_logger
from app.workers.correlation_worker import evaluate_correlation
from app.workers.notification_worker import notify_if_critical

logger = get_logger(__name__)

# Maps a batch's `source` to the adapter that turns its raw, source-native
# payload shape into NormalizedLog-shaped fields. "synthetic" has no
# adapter by design — synthetic payloads are already NormalizedLog-shaped.
ADAPTER_REGISTRY: dict[str, Callable[[dict], dict]] = {
    LogSource.WAZUH.value: wazuh.transform,
    LogSource.AWS_CLOUDTRAIL.value: cloudtrail.transform,
    LogSource.AWS_GUARDDUTY.value: guardduty.transform,
    LogSource.CLOUDLENS.value: cloudlens.transform,
}

# Queuing a Celery task means publishing to the broker, which is a blocking
# call — cap it, so a slow/unreachable broker degrades to "task wasn't
# queued this time" instead of hanging (the exact failure mode ADR-005
# exists to prevent).
_QUEUE_TIMEOUT_SECONDS = 2.0


async def _queue_task(task, alert_id: str, *, task_name: str) -> None:
    loop = asyncio.get_running_loop()
    try:
        await asyncio.wait_for(
            loop.run_in_executor(None, task.delay, alert_id),
            timeout=_QUEUE_TIMEOUT_SECONDS,
        )
    except Exception as e:
        logger.warning(f"Failed to queue {task_name} task", alert_id=alert_id, error=str(e))


def queue_post_ingest_tasks(background_tasks: BackgroundTasks, alert_ids: list[str]) -> None:
    """
    Queue threat-intel enrichment (SS-025/026), attack-chain correlation
    (SS-027/028/030), and critical-alert notification (SS-056) for each
    accepted alert, as FastAPI background tasks (run after the response
    is sent, ADR-005) so none of them ever delay a caller's response.
    Shared by every router that accepts logs (POST /api/v1/ingest,
    POST /api/v1/cloud/findings). Notification is a no-op for anything
    below critical severity — decided inside the task itself, same as
    enrichment's own no-op-if-nothing-to-enrich gating.
    """
    for alert_id in alert_ids:
        background_tasks.add_task(_queue_task, enrich_alert, alert_id, task_name="enrichment")
        background_tasks.add_task(_queue_task, evaluate_correlation, alert_id, task_name="correlation")
        background_tasks.add_task(_queue_task, notify_if_critical, alert_id, task_name="notification")


async def process_ingest_batch(
    logs: list[dict],
    tenant_id: str,
    source: str = "synthetic",
) -> dict:
    """
    Validate a batch of raw log dicts and ingest them.

    Args:
        logs: List of raw log dicts. For source == "synthetic" these are
              expected to already be NormalizedLog-shaped; for any source
              in ADAPTER_REGISTRY, each dict is that source's own raw
              payload shape and is passed through the matching adapter
              (SS-018/019/020) before validation.
        tenant_id: Owning tenant ID (from the authenticated JWT).
        source: Log source for this batch (wazuh, synthetic, aws_cloudtrail, etc.)

    Returns:
        dict with accepted count, rejected count, and list of alert_ids.

    Raises:
        IngestionError: if source isn't "synthetic" and has no registered
        adapter — an unrecognized source fails the whole batch clearly
        rather than silently falling through to the synthetic path.
    """
    transform = ADAPTER_REGISTRY.get(source)
    if source != LogSource.SYNTHETIC.value and transform is None:
        raise IngestionError(f"Unknown log source '{source}' — no adapter registered for it.")

    accepted: list[str] = []
    rejected: list[dict] = []
    validated_logs: list[dict] = []

    for i, log in enumerate(logs):
        try:
            if transform is not None:
                log = transform(log)

            # tenant_id always comes from the caller's authenticated identity
            # (SS-016) — any tenant_id the log itself carries is ignored, not
            # merely defaulted, so a batch can't smuggle a different tenant
            # via an individual log object.
            log["tenant_id"] = tenant_id
            if "source" not in log or not log["source"]:
                log["source"] = source

            # Validate against NormalizedLog schema
            validated = NormalizedLog(**log)
            validated_logs.append(validated.model_dump(mode="json"))
            accepted.append(validated.alert_id)

        except ValidationError as e:
            rejected.append({
                "index": i,
                "error": str(e),
                "raw": {k: str(v)[:100] for k, v in log.items()},
            })
            logger.warning("Log validation failed", index=i, error=str(e))

    # Bulk write to OpenSearch
    if validated_logs:
        written = await bulk_index_logs(validated_logs)
        logger.info("Batch ingested", accepted=len(accepted), rejected=len(rejected), written=written)

    return {
        "accepted": len(accepted),
        "rejected": len(rejected),
        "alert_ids": accepted,
        "errors": rejected if rejected else None,
    }