"""
SafeSOC — Alerts API
GET /api/v1/alerts — paginated alert search with filters.
"""

from typing import Optional

from fastapi import APIRouter, Query

from app.db.opensearch import search_alerts

router = APIRouter(prefix="/api/v1", tags=["alerts"])


@router.get("/alerts")
async def get_alerts(
    tenant_id: str = Query(..., description="Tenant ID (required)"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    log_type: Optional[str] = Query(None, description="Filter by log type"),
    source: Optional[str] = Query(None, description="Filter by source"),
    host_id: Optional[str] = Query(None, description="Filter by endpoint"),
    timerange_hours: int = Query(24, ge=1, le=720, description="Hours to look back"),
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(50, ge=1, le=500, description="Results per page"),
):
    """
    Search alerts with mandatory tenant_id filter.
    Returns paginated results sorted by timestamp descending.
    """
    result = await search_alerts(
        tenant_id=tenant_id,
        severity=severity,
        log_type=log_type,
        source=source,
        host_id=host_id,
        timerange_hours=timerange_hours,
        page=page,
        size=size,
    )
    return result