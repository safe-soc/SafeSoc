"""
SafeSOC — Compliance Center Schemas
Response shapes for GET /api/v1/compliance/requirements and
GET /api/v1/compliance/requirements/{id}. See services/compliance.py
for how these are computed and core/compliance_mapping.py for the
static requirement text each one is built from.
"""

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel

from app.core.enums import ComplianceFramework, ComplianceStatus, CorrelationPattern, IncidentStatus


class RelatedIncidentRef(BaseModel):
    id: uuid.UUID
    status: IncidentStatus
    category: Optional[CorrelationPattern] = None
    created_at: datetime


class RelatedInvestigationRef(BaseModel):
    session_id: uuid.UUID
    incident_id: uuid.UUID
    created_at: datetime


class ComplianceRequirementSummary(BaseModel):
    id: str
    framework: ComplianceFramework
    title: str
    reference: str
    status: ComplianceStatus
    evidence_summary: str
    evidence_count: int
    last_evaluated: datetime


class ComplianceFrameworkSummary(BaseModel):
    framework: ComplianceFramework
    title: str
    total_requirements: int
    evidence_available: int
    partially_supported: int
    gaps: int
    not_assessable: int


class CompliancePostureResponse(BaseModel):
    requirements_assessed: int
    evidence_available: int
    partially_supported: int
    gaps: int
    not_assessable: int
    frameworks: list[ComplianceFrameworkSummary]
    requirements: list[ComplianceRequirementSummary]


class ComplianceRequirementDetail(BaseModel):
    id: str
    framework: ComplianceFramework
    title: str
    reference: str
    authoritative_source: str
    requirement_summary: str
    what_safesoc_can_observe: str
    what_safesoc_cannot_verify: str
    recommended_action: str

    status: ComplianceStatus
    evidence_summary: str
    evidence_count: int
    # Requirement-specific structured numbers (e.g. {"audit_events": 12,
    # "incidents": 3} or {"configured_retention_days": 90,
    # "required_retention_days": 180}) — the detail view's own "SafeSOC
    # evidence" breakdown, kept generic so each requirement type can
    # surface whatever numbers are actually meaningful for it.
    metrics: dict[str, int]
    last_evaluated: datetime

    related_incidents: list[RelatedIncidentRef]
    related_investigations: list[RelatedInvestigationRef]
