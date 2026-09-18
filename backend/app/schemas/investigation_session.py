"""
SafeSOC — Investigation Session Schemas
Request/response models for persistent, incident-scoped investigation
sessions (services/investigation_session.py). `data` in
InvestigationSessionDetail.evidence is always freshly retrieved, never
a stored snapshot — see that service module's docstring for why.
"""

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel

from app.core.enums import FindingCategory, FindingOrigin, InvestigationActionStatus


class InvestigationSessionSummary(BaseModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    created_by_user_id: uuid.UUID
    created_at: datetime


class InvestigationTurnResponse(BaseModel):
    id: uuid.UUID
    asked_by_user_id: uuid.UUID
    question: str
    answer: str
    is_fallback: bool
    created_at: datetime


class InvestigationFindingResponse(BaseModel):
    id: uuid.UUID
    text: str
    category: FindingCategory
    origin: FindingOrigin
    created_by_user_id: Optional[uuid.UUID]
    confirmed_by_user_id: Optional[uuid.UUID]
    confirmed_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime


class InvestigationActionResponse(BaseModel):
    id: uuid.UUID
    description: str
    status: InvestigationActionStatus
    created_by_user_id: uuid.UUID
    completed_by_user_id: Optional[uuid.UUID]
    completed_at: Optional[datetime]
    created_at: datetime


class InvestigationNoteResponse(BaseModel):
    id: uuid.UUID
    author_user_id: uuid.UUID
    body: str
    created_at: datetime


class EvidenceSummary(BaseModel):
    """
    The "KNOWN" list — hosts/users/MITRE techniques/alert count,
    always re-derived live from the same aggregation
    services/incident_narrative.py's Attack-Chain Summary already uses
    (mcp.tools.incident_narrative_data), never persisted or cached.
    """
    hosts: list[str]
    users: list[str]
    mitre_techniques: list[str]
    alert_count: int


class InvestigationSessionDetail(BaseModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    created_by_user_id: uuid.UUID
    created_at: datetime
    evidence: EvidenceSummary
    turns: list[InvestigationTurnResponse]
    findings: list[InvestigationFindingResponse]
    actions: list[InvestigationActionResponse]
    notes: list[InvestigationNoteResponse]


class AskQuestionRequest(BaseModel):
    question: str


class AskQuestionResponse(BaseModel):
    turn: InvestigationTurnResponse


class CreateFindingRequest(BaseModel):
    text: str
    category: FindingCategory = FindingCategory.HYPOTHESIS


class UpdateFindingRequest(BaseModel):
    category: FindingCategory


class CreateActionRequest(BaseModel):
    description: str


class UpdateActionRequest(BaseModel):
    status: InvestigationActionStatus


class CreateNoteRequest(BaseModel):
    body: str
