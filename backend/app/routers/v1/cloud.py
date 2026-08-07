"""
SafeSOC — Cloud Findings Bridge
POST /api/v1/cloud/findings — receives a batch of raw CloudLens Finding
dicts pushed from cloud/AWS-IAM-backend/engine/safesoc_bridge.py after a
scan completes (SS-039), and routes them through the same pipeline
POST /api/v1/ingest uses (services/ingestion.py:process_ingest_batch,
source="cloudlens" -> app/adapters/cloudlens.py:transform, SS-038).

GET /api/v1/cloud/summary — aggregate stats for cloud-sourced alerts
(SS-040). Cloud-sourced alerts are already queryable via the generic
GET /api/v1/alerts?source=cloudlens (existing filter logic, confirmed
rather than duplicated here — see tests/test_cloud_router.py and this
issue's Docker verification notes); this endpoint only adds the one
thing that generic paginated list genuinely can't: aggregate counts.

Authenticated via a shared service token (X-Service-Token header), not
a user JWT: CloudLens is a same-deployment backend service pushing data
on a scan's behalf, not an interactive user (SS-039).
"""

import hmac

from fastapi import APIRouter, BackgroundTasks, Depends, Header, Query

from app.core.config import settings
from app.core.dependencies import CurrentUser, get_current_user
from app.core.exceptions import IngestionError, InvalidServiceTokenError
from app.core.enums import LogSource
from app.db.opensearch import get_cloud_summary
from app.services.ingestion import process_ingest_batch, queue_post_ingest_tasks
from app.utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/cloud", tags=["cloud"])


async def verify_service_token(x_service_token: str = Header(default="")) -> None:
    """
    Reject unless the caller presents the configured CloudLens service
    token. Closed by default: an unset CLOUDLENS_SERVICE_TOKEN rejects
    every request rather than silently allowing an unauthenticated one.
    Uses a constant-time comparison so response timing can't be used to
    recover the token byte-by-byte (SS-067).
    """
    if not settings.CLOUDLENS_SERVICE_TOKEN or not hmac.compare_digest(x_service_token, settings.CLOUDLENS_SERVICE_TOKEN):
        raise InvalidServiceTokenError()


@router.post("/findings", dependencies=[Depends(verify_service_token)])
async def receive_findings(payload: dict, background_tasks: BackgroundTasks):
    """
    Accept a batch of raw CloudLens Finding dicts and ingest them.

    Body: {"tenant_id": "...", "findings": [{...}, ...]}

    Reuses the exact same batch-processing pipeline POST /api/v1/ingest
    uses, so partial-success semantics (each finding validated
    independently, per CLAUDE.md), enrichment, and correlation are all
    identical. CloudLens's own send is fire-and-forget (SS-039) — this
    endpoint's response is only observed if CloudLens chooses to log it.
    """
    tenant_id = payload.get("tenant_id")
    findings = payload.get("findings")
    if not tenant_id or not isinstance(findings, list):
        raise IngestionError("Request must contain 'tenant_id' and a 'findings' list")

    result = await process_ingest_batch(logs=findings, tenant_id=tenant_id, source=LogSource.CLOUDLENS.value)

    queue_post_ingest_tasks(background_tasks, result["alert_ids"])

    logger.info(
        "CloudLens findings synced",
        tenant_id=tenant_id,
        accepted=result["accepted"],
        rejected=result["rejected"],
    )

    return {
        "accepted": result["accepted"],
        "rejected": result["rejected"],
        "alert_ids": result["alert_ids"],
        "errors": result.get("errors"),
    }


@router.get("/summary")
async def summary(
    timerange_hours: int = Query(24, ge=1, le=720, description="Hours to look back"),
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    Aggregate stats for cloud-sourced alerts scoped to the authenticated
    tenant: total count, breakdowns by severity and category, and the
    number of distinct affected resources.
    """
    return await get_cloud_summary(str(current_user.tenant_id), timerange_hours)
