"""
SafeSOC — Ingestion Service
Validates incoming logs against NormalizedLog schema,
normalizes via adapters, and writes to OpenSearch.
"""

from typing import Optional

from pydantic import ValidationError

from app.db.opensearch import bulk_index_logs
from app.schemas.log import NormalizedLog
from app.utils.logger import get_logger

logger = get_logger(__name__)


async def process_ingest_batch(
    logs: list[dict],
    tenant_id: str,
    source: str = "synthetic",
) -> dict:
    """
    Validate a batch of raw log dicts and ingest them.

    Args:
        logs: List of raw log dicts (already in NormalizedLog format
              or converted by an adapter).
        tenant_id: Owning tenant ID (from API key or JWT).
        source: Log source override (wazuh, synthetic, aws_cloudtrail, etc.)

    Returns:
        dict with accepted count, rejected count, and list of alert_ids.
    """
    accepted: list[str] = []
    rejected: list[dict] = []
    validated_logs: list[dict] = []

    for i, log in enumerate(logs):
        try:
            # Inject tenant_id and source if not provided by the adapter
            if "tenant_id" not in log or not log["tenant_id"]:
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