"""
SafeSOC — Ingestion Service
Dispatches raw, source-specific payloads through the matching adapter,
validates the result against NormalizedLog schema, and writes to OpenSearch.
"""

from typing import Callable, Optional

from pydantic import ValidationError

from app.adapters import cloudtrail, guardduty, wazuh
from app.core.enums import LogSource
from app.core.exceptions import IngestionError
from app.db.opensearch import bulk_index_logs
from app.schemas.log import NormalizedLog
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Maps a batch's `source` to the adapter that turns its raw, source-native
# payload shape into NormalizedLog-shaped fields. "synthetic" has no
# adapter by design — synthetic payloads are already NormalizedLog-shaped.
ADAPTER_REGISTRY: dict[str, Callable[[dict], dict]] = {
    LogSource.WAZUH.value: wazuh.transform,
    LogSource.AWS_CLOUDTRAIL.value: cloudtrail.transform,
    LogSource.AWS_GUARDDUTY.value: guardduty.transform,
}


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