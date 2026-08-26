"""
SafeSOC — Threat Analytics API
GET /api/v1/threat-analytics — tenant-scoped rollup of correlation-
pattern trends over a rolling window (SS-111). Requires a valid JWT
(SS-015); tenant_id is derived from the token, not the caller (SS-016).
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, get_current_user
from app.db.postgresql import get_db
from app.services.threat_analytics import ThreatAnalyticsResponse, get_threat_analytics

router = APIRouter(prefix="/api/v1/threat-analytics", tags=["threat-analytics"])


@router.get("", response_model=ThreatAnalyticsResponse)
async def get_analytics(
    window_days: int = Query(7, ge=1, le=90, description="Rolling window size in days"),
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Trend rollup for the authenticated tenant: current vs. the equal-length window immediately before it, sorted by current count descending."""
    return await get_threat_analytics(db, current_user.tenant_id, window_days=window_days)
