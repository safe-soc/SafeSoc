"""
SafeSOC — Incident Schemas
Request/response models for incident CRUD, lifecycle transitions
(SS-036), and post-creation alert linking + investigation notes (SS-037).
"""

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from app.core.enums import CorrelationPattern, IncidentStatus


class IncidentCreateRequest(BaseModel):
    alert_ids: list[str] = Field(default_factory=list)

    model_config = {
        "json_schema_extra": {
            "example": {"alert_ids": ["alert-1", "alert-2"]},
        }
    }


class IncidentTransitionRequest(BaseModel):
    to_status: IncidentStatus

    model_config = {
        "json_schema_extra": {
            "example": {"to_status": "investigating"},
        }
    }


class IncidentResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    status: IncidentStatus
    alert_ids: list[str]
    assigned_analyst_id: Optional[uuid.UUID]
    # SS-094: the detected chain's pattern/confidence at creation (or
    # last merge) — null for a manually-created incident, which has no
    # detected chain.
    category: Optional[CorrelationPattern]
    confidence: Optional[float]
    created_at: datetime
    updated_at: datetime


class IncidentListResponse(BaseModel):
    total: int
    page: int
    size: int
    pages: int
    incidents: list[IncidentResponse]


class AlertLinkRequest(BaseModel):
    alert_id: str

    model_config = {
        "json_schema_extra": {
            "example": {"alert_id": "alert-3"},
        }
    }


class IncidentNoteCreateRequest(BaseModel):
    body: str

    model_config = {
        "json_schema_extra": {
            "example": {"body": "Confirmed lateral movement to FINANCE-DB-01; escalating."},
        }
    }


class IncidentNoteResponse(BaseModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    author_user_id: uuid.UUID
    body: str
    created_at: datetime
