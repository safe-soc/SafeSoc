"""
SafeSOC — Alerts API
GET /api/v1/alerts — paginated alert search with filters, free-text
search (`q`) and a triage-status filter.
POST /api/v1/alerts/{alert_id}/acknowledge, .../dismiss (with a
reason), .../restore — analyst triage actions (SS-107).
Requires a valid JWT (SS-015); tenant_id is derived from the token,
not the caller-supplied query parameter (SS-016).
"""

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, ensure_tenant_matches, get_current_user, require_role
from app.core.enums import TriageStatus, UserRole
from app.db.opensearch import get_alert_severity_summary, search_alerts
from app.db.postgresql import get_db
from app.models.alert_annotation import AlertAnnotation
from app.schemas.alerts import AlertAnnotationResponse, AlertDismissRequest
from app.services.alert_annotations import (
    acknowledge_alert,
    dismiss_alert,
    get_alert_ids_for_triage_status,
    get_annotations_for_alert_ids,
    restore_alert,
)

router = APIRouter(prefix="/api/v1", tags=["alerts"])


def _annotation_to_response(annotation: AlertAnnotation) -> AlertAnnotationResponse:
    return AlertAnnotationResponse(
        alert_id=annotation.alert_id,
        acknowledged=annotation.acknowledged,
        dismissed=annotation.dismissed,
        dismiss_reason=annotation.dismiss_reason,
        dismiss_note=annotation.dismiss_note,
        updated_by_user_id=annotation.updated_by_user_id,
        updated_at=annotation.updated_at,
    )


@router.get("/alerts")
async def get_alerts(
    current_user: CurrentUser = Depends(get_current_user),
    tenant_id: Optional[str] = Query(
        None, description="Optional; if provided must match the authenticated tenant"
    ),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    log_type: Optional[str] = Query(None, description="Filter by log type"),
    source: Optional[str] = Query(None, description="Filter by source"),
    host_id: Optional[str] = Query(None, description="Filter by endpoint"),
    timerange_hours: int = Query(24, ge=1, le=720, description="Hours to look back"),
    q: Optional[str] = Query(
        None,
        max_length=200,
        description="Free-text search across host, user, action, description, source/destination IP, rule and MITRE technique",
    ),
    triage: Optional[TriageStatus] = Query(None, description="Filter by triage status; omit for all"),
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(50, ge=1, le=500, description="Results per page"),
    db: AsyncSession = Depends(get_db),
):
    """
    Search alerts scoped to the authenticated tenant.

    Requires a valid JWT. tenant_id is always derived from the
    authenticated token; a tenant_id query parameter is only accepted if
    it matches the token's tenant_id, otherwise the request is rejected.
    Returns paginated results sorted by timestamp descending, each
    merged with its acknowledged/dismissed triage state (SS-107) —
    defaulting to False for an alert with no AlertAnnotation row yet.
    `q` and `triage` narrow the results (and the total) like any other filter.
    """
    ensure_tenant_matches(current_user, tenant_id)

    alert_ids_include = alert_ids_exclude = None
    if triage is not None:
        alert_ids_include, alert_ids_exclude = await get_alert_ids_for_triage_status(
            db, current_user.tenant_id, triage
        )

    result = await search_alerts(
        tenant_id=str(current_user.tenant_id),
        severity=severity,
        log_type=log_type,
        source=source,
        host_id=host_id,
        timerange_hours=timerange_hours,
        page=page,
        size=size,
        q=q,
        alert_ids_include=alert_ids_include,
        alert_ids_exclude=alert_ids_exclude,
    )

    alert_ids = [alert["alert_id"] for alert in result["alerts"] if alert.get("alert_id")]
    annotations = await get_annotations_for_alert_ids(db, current_user.tenant_id, alert_ids)
    for alert in result["alerts"]:
        annotation = annotations.get(alert.get("alert_id"))
        alert["acknowledged"] = annotation.acknowledged if annotation else False
        alert["dismissed"] = annotation.dismissed if annotation else False
        alert["dismiss_reason"] = annotation.dismiss_reason.value if annotation and annotation.dismiss_reason else None
        alert["dismiss_note"] = annotation.dismiss_note if annotation else None

    return result


@router.get("/alerts/summary")
async def get_alerts_summary(
    current_user: CurrentUser = Depends(get_current_user),
    timerange_hours: int = Query(24, ge=1, le=720, description="Hours to look back"),
    host_id: Optional[str] = Query(None, description="Scope the summary to a single host"),
):
    """
    Severity breakdown for the same tenant+time-window population
    GET /api/v1/alerts?timerange_hours=<n>&host_id=<id> pages through —
    an aggregation (total count + per-severity counts), not a page of
    documents, so it isn't capped by that endpoint's `size` limit. Use
    this instead of deriving severity distribution from a single
    fetched page of /api/v1/alerts results. `host_id` scopes it to one
    endpoint (the endpoint detail page's own severity breakdown) exactly
    like /api/v1/alerts' own host_id filter.
    """
    return await get_alert_severity_summary(
        tenant_id=str(current_user.tenant_id),
        timerange_hours=timerange_hours,
        host_id=host_id,
    )


@router.post("/alerts/{alert_id}/acknowledge", response_model=AlertAnnotationResponse)
async def acknowledge(
    alert_id: str,
    current_user: CurrentUser = Depends(require_role(UserRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    """Mark an alert acknowledged (SS-107) — tenant-scoped, audit-logged."""
    annotation = await acknowledge_alert(db, current_user.tenant_id, alert_id, current_user.user_id)
    return _annotation_to_response(annotation)


@router.post("/alerts/{alert_id}/dismiss", response_model=AlertAnnotationResponse)
async def dismiss(
    alert_id: str,
    payload: AlertDismissRequest,
    current_user: CurrentUser = Depends(require_role(UserRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    """
    Mark an alert dismissed with a reason (SS-107) — tenant-scoped,
    audit-logged with the reason and note. `note` is required when
    `reason` is "other" (422 otherwise).
    """
    annotation = await dismiss_alert(
        db, current_user.tenant_id, alert_id, current_user.user_id, reason=payload.reason, note=payload.note
    )
    return _annotation_to_response(annotation)


@router.post("/alerts/{alert_id}/restore", response_model=AlertAnnotationResponse)
async def restore(
    alert_id: str,
    current_user: CurrentUser = Depends(require_role(UserRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    """Undo a dismissal: clears dismissed, reason and note. Audit-logged as alert.restored."""
    annotation = await restore_alert(db, current_user.tenant_id, alert_id, current_user.user_id)
    return _annotation_to_response(annotation)
