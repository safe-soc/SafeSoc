"""
SafeSOC — Incident Schemas
Request/response models for incident CRUD and lifecycle transitions.
"""

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from app.core.enums import IncidentStatus


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
    created_at: datetime
    updated_at: datetime


class IncidentListResponse(BaseModel):
    total: int
    page: int
    size: int
    pages: int
    incidents: list[IncidentResponse]
