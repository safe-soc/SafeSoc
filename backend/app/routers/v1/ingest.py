"""
SafeSOC — Ingestion API Endpoint
POST /api/v1/ingest — accepts single or batch security logs.
"""

from fastapi import APIRouter

from app.core.config import settings
from app.core.exceptions import IngestionError
from app.schemas.log import NormalizedLog
from app.services.ingestion import process_ingest_batch
from app.utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1", tags=["ingestion"])


@router.post("/ingest")
async def ingest_logs(payload: dict):
    """
    Ingest security logs into SafeSOC.

    Accepts:
        - Single log object: {"log": {...}}
        - Batch of logs:    {"logs": [{...}, {...}]}

    All logs are validated against NormalizedLog schema before writing.
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

    # Extract tenant_id from payload or default (auth middleware handles this later)
    tenant_id = payload.get("tenant_id", "default-tenant")

    # Process the batch
    result = await process_ingest_batch(
        logs=logs,
        tenant_id=tenant_id,
        source=payload.get("source", "synthetic"),
    )

    return {
        "accepted": result["accepted"],
        "rejected": result["rejected"],
        "alert_ids": result["alert_ids"],
        "errors": result.get("errors"),
    }