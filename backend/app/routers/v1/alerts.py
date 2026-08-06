"""
SafeSOC — Alerts API
GET /api/v1/alerts — paginated alert search with filters.
Requires a valid JWT (SS-015); tenant_id is derived from the token,
not the caller-supplied query parameter (SS-016).
"""

from typing import Optional

from fastapi import APIRouter, Depends, Query

from app.core.dependencies import CurrentUser, ensure_tenant_matches, get_current_user
from app.db.opensearch import search_alerts

router = APIRouter(prefix="/api/v1", tags=["alerts"])


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
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(50, ge=1, le=500, description="Results per page"),
):
    """
    Search alerts scoped to the authenticated tenant.

    Requires a valid JWT. tenant_id is always derived from the
    authenticated token; a tenant_id query parameter is only accepted if
    it matches the token's tenant_id, otherwise the request is rejected.
    Returns paginated results sorted by timestamp descending.
    """
    ensure_tenant_matches(current_user, tenant_id)

    result = await search_alerts(
        tenant_id=str(current_user.tenant_id),
        severity=severity,
        log_type=log_type,
        source=source,
        host_id=host_id,
        timerange_hours=timerange_hours,
        page=page,
        size=size,
    )
    return result
