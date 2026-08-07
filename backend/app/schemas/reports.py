"""
SafeSOC — Report Schemas
Response models for the reports listing API (SS-054).
"""

from datetime import datetime

from pydantic import BaseModel


class ReportSummary(BaseModel):
    filename: str
    generated_at: datetime
    size_bytes: int


class ReportListResponse(BaseModel):
    reports: list[ReportSummary]
