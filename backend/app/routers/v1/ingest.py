"""
SafeSOC — Ingestion API Endpoint
POST /api/v1/ingest — accepts single or batch security logs.
Requires a valid JWT (SS-015); tenant_id is derived from the token,
not the caller-supplied payload (SS-016).
"""

import asyncio

from fastapi import APIRouter, BackgroundTasks, Depends

from app.core.config import settings
from app.core.dependencies import CurrentUser, ensure_tenant_matches, get_current_user
from app.core.exceptions import IngestionError
from app.schemas.log import NormalizedLog
from app.services.ingestion import process_ingest_batch
from app.tasks.enrichment import enrich_alert
from app.utils.logger import get_logger
from app.workers.correlation_worker import evaluate_correlation

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1", tags=["ingestion"])

# Queuing a Celery task means publishing to the broker, which is a blocking
# call — cap it, so a slow/unreachable broker degrades to "task wasn't
# queued this time" instead of hanging (the exact failure mode ADR-005
# exists to prevent). This runs as a FastAPI background task (after the
# response is already sent), not awaited inline in the route, so it can
# never add to ingestion response time in the first place.
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


@router.post("/ingest")
async def ingest_logs(
    payload: dict,
    background_tasks: BackgroundTasks,
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Ingest security logs into SafeSOC.

    Accepts:
        - Single log object: {"log": {...}}
        - Batch of logs:    {"logs": [{...}, {...}]}

    Requires a valid JWT. tenant_id is always derived from the
    authenticated token; a tenant_id in the payload is only accepted if
    it matches the token's tenant_id (otherwise the request is rejected),
    and is otherwise ignored entirely, including on individual logs
    within a batch.

    All logs are validated against NormalizedLog schema before writing.
    Threat-intel enrichment (SS-025/026) and attack-chain correlation
    (SS-027/028/030) for each accepted log are both queued as background
    tasks (Celery, ADR-005) and never delay this response.
    """
    # Determine if single log or batch
    if "log" in payload:
        logs = [payload["log"]]
    elif "logs" in payload:
        logs = payload["logs"]
    else:
        raise IngestionError("Request must contain 'log' (single) or 'logs' (batch)")

    if not isinstance(logs, list):
        raise IngestionError("'logs' must be a list")

    if len(logs) > settings.INGEST_BATCH_SIZE:
        raise IngestionError(
            f"Batch size {len(logs)} exceeds maximum of {settings.INGEST_BATCH_SIZE} logs per request"
        )

    ensure_tenant_matches(current_user, payload.get("tenant_id"))
    tenant_id = str(current_user.tenant_id)

    # Process the batch
    result = await process_ingest_batch(
        logs=logs,
        tenant_id=tenant_id,
        source=payload.get("source", "synthetic"),
    )

    for alert_id in result["alert_ids"]:
        background_tasks.add_task(_queue_task, enrich_alert, alert_id, task_name="enrichment")
        background_tasks.add_task(_queue_task, evaluate_correlation, alert_id, task_name="correlation")

    return {
        "accepted": result["accepted"],
        "rejected": result["rejected"],
        "alert_ids": result["alert_ids"],
        "errors": result.get("errors"),
    }
