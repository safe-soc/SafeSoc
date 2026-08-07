"""
SafeSOC — Endpoints API
GET /api/v1/endpoints — known hosts with their current risk score/level
(SS-032/SS-033), sorted by risk descending, scoped to the authenticated
tenant. Requires a valid JWT (SS-015); tenant_id is derived from the
token, not the caller (SS-016).
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, get_current_user
from app.db.postgresql import get_db
from app.models.endpoint import Endpoint
from app.schemas.endpoints import EndpointResponse
from app.services.risk_scoring import list_endpoints

router = APIRouter(prefix="/api/v1/endpoints", tags=["endpoints"])


def _to_response(endpoint: Endpoint) -> EndpointResponse:
    return EndpointResponse(
        id=endpoint.id,
        tenant_id=endpoint.tenant_id,
        host_id=endpoint.host_id,
        risk_score=endpoint.risk_score,
        risk_level=endpoint.risk_level,
        updated_at=endpoint.updated_at,
    )


@router.get("", response_model=list[EndpointResponse])
async def list_all(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List known hosts for the authenticated tenant, sorted by risk score descending."""
    endpoints = await list_endpoints(db, current_user.tenant_id)
    return [_to_response(endpoint) for endpoint in endpoints]
