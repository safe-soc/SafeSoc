"""
SafeSOC — Reports API
GET /api/v1/reports — list generated PDF reports (SS-052) for the
caller's tenant. GET /api/v1/reports/{filename} — download one.
Requires a valid JWT (SS-015); tenant_id is derived from the token
(SS-016), scoping both listing and download so a filename that exists
under a different tenant is indistinguishable from one that doesn't
exist at all — the same 404-for-both pattern get_incident uses.
"""

from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse

from app.core.dependencies import CurrentUser, get_current_user
from app.core.exceptions import ReportNotFoundError
from app.schemas.reports import ReportListResponse, ReportSummary
from app.services.reporting import get_report_path, list_reports

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])


@router.get("", response_model=ReportListResponse)
async def list_all(current_user: CurrentUser = Depends(get_current_user)):
    """List generated reports for the authenticated tenant, newest first. Empty list if none have been generated yet."""
    reports = list_reports(current_user.tenant_id)
    return ReportListResponse(
        reports=[
            ReportSummary(filename=r.filename, generated_at=r.generated_at, size_bytes=r.size_bytes)
            for r in reports
        ]
    )


@router.get("/{filename}")
async def download(filename: str, current_user: CurrentUser = Depends(get_current_user)):
    """
    Download a specific report, scoped to the authenticated tenant.

    Raises:
        ReportNotFoundError: (404) if no such file exists under this
        tenant's own report directory — including a filename that
        exists under a *different* tenant's, so it can't be used to
        distinguish "not yours" from "doesn't exist."
    """
    path = get_report_path(current_user.tenant_id, filename)
    if path is None:
        raise ReportNotFoundError(filename)
    return FileResponse(path, media_type="application/pdf", filename=filename)
