"""
SafeSOC — Endpoints API
GET /api/v1/endpoints — known hosts with their current risk score/level
(SS-032/SS-033), sorted by risk descending, scoped to the authenticated
tenant. Requires a valid JWT (SS-015); tenant_id is derived from the
token, not the caller (SS-016).
"""

from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, get_current_user
from app.db.postgresql import get_db
from app.models.endpoint import Endpoint
from app.models.endpoint_software import EndpointSoftware
from app.schemas.endpoints import EndpointResponse, EndpointSoftwareResponse
from app.schemas.reports import EndpointReportRequest, InvestigationReportResponse
from app.services.investigation_report import InvestigationQA, generate_endpoint_report
from app.services.risk_scoring import list_endpoints
from app.services.software_inventory import list_endpoint_software

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


def _software_to_response(software: EndpointSoftware) -> EndpointSoftwareResponse:
    return EndpointSoftwareResponse(
        id=software.id,
        host_id=software.host_id,
        name=software.name,
        version=software.version,
        category=software.category,
        vulnerabilities=software.vulnerabilities,
        updated_at=software.updated_at,
    )


@router.get("", response_model=list[EndpointResponse])
async def list_all(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List known hosts for the authenticated tenant, sorted by risk score descending."""
    endpoints = await list_endpoints(db, current_user.tenant_id)
    return [_to_response(endpoint) for endpoint in endpoints]


@router.get("/{host_id}/software", response_model=list[EndpointSoftwareResponse])
async def list_software(
    host_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Software/vulnerability inventory for one host, scoped to the
    authenticated tenant. An empty list means no inventory data exists
    for this host — not an error (most real deployments would have
    this synced from an EDR/MDM agent; this demo populates it via
    injector/simulate.py's seeding step for hosts it creates).
    """
    software = await list_endpoint_software(db, current_user.tenant_id, host_id)
    return [_software_to_response(item) for item in software]


@router.post("/{host_id}/report", response_model=InvestigationReportResponse)
async def generate_report(
    host_id: str,
    payload: Optional[EndpointReportRequest] = None,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Generate a PDF security investigation report scoped to this
    endpoint (risk, alerts, associated incidents, attack chain, users,
    software/vulnerabilities, MITRE techniques — see
    services/investigation_report.py). If the caller's own
    Investigation Assistant session already answered questions about
    this host, pass them as session_qa so the report's "Investigation /
    AI Analyst Findings" section includes them verbatim instead of
    generating a separate summary. Download via the returned
    download_url — the existing GET /api/v1/reports/{filename} route.
    """
    session_qa = None
    if payload and payload.session_qa:
        session_qa = [
            InvestigationQA(question=qa.question, answer=qa.answer, is_fallback=qa.is_fallback)
            for qa in payload.session_qa
        ]
    path, generated_at = await generate_endpoint_report(db, current_user.tenant_id, host_id, session_qa=session_qa)
    return InvestigationReportResponse(
        filename=path.name,
        generated_at=generated_at,
        size_bytes=path.stat().st_size,
        download_url=f"/api/v1/reports/{path.name}",
    )
