"""
SafeSOC — Ingestion API Endpoint
POST /api/v1/ingest — accepts single or batch security logs.
Requires a valid JWT (SS-015); tenant_id is derived from the token,
not the caller-supplied payload (SS-016).
"""

from fastapi import APIRouter, Depends

from app.core.config import settings
from app.core.dependencies import CurrentUser, ensure_tenant_matches, get_current_user
from app.core.exceptions import IngestionError
from app.schemas.log import NormalizedLog
from app.services.ingestion import process_ingest_batch
from app.utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1", tags=["ingestion"])


@router.post("/ingest")
async def ingest_logs(payload: dict, current_user: CurrentUser = Depends(get_current_user)):
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

    return {
        "accepted": result["accepted"],
        "rejected": result["rejected"],
        "alert_ids": result["alert_ids"],
        "errors": result.get("errors"),
    }