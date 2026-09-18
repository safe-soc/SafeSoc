"""
SafeSOC — Report Schemas
Response models for the reports listing API (SS-054), plus the
on-demand investigation-report generation request/response shapes
(incident/endpoint "Generate Report" — a separate feature from the
scheduled weekly digest above, sharing this file for the same reason
services/investigation_report.py sits next to services/reporting.py).
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class ReportSummary(BaseModel):
    filename: str
    generated_at: datetime
    size_bytes: int


class ReportListResponse(BaseModel):
    reports: list[ReportSummary]


class InvestigationSessionQA(BaseModel):
    """
    One already-answered question from the analyst's own SafeSOC
    Investigation Assistant session for this endpoint, passed through
    by the frontend so the endpoint report's "Investigation / AI
    Analyst Findings" section can include it verbatim instead of
    generating a separate summary (see investigation_report.py's
    gather_endpoint_report_data docstring).
    """

    question: str
    answer: str
    is_fallback: bool = False


class EndpointReportRequest(BaseModel):
    session_qa: Optional[list[InvestigationSessionQA]] = None


class InvestigationReportResponse(BaseModel):
    filename: str
    generated_at: datetime
    size_bytes: int
    download_url: str
