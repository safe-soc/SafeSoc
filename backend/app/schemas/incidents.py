"""
SafeSOC — Incident Schemas
Request/response models for incident CRUD, lifecycle transitions
(SS-036), and post-creation alert linking + investigation notes (SS-037).
"""

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, model_validator

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


class IncidentAssignRequest(BaseModel):
    assignee_user_id: uuid.UUID

    model_config = {
        "json_schema_extra": {
            "example": {"assignee_user_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"},
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
    # SS-106: free-form analyst-authored labels, distinct from `category`.
    tags: list[str]
    created_at: datetime
    updated_at: datetime
    # SS-108: populated only by the bulk alert-link endpoint's batch
    # path (AlertLinkRequest.alert_ids); null for every other
    # IncidentResponse-returning endpoint, including single-alert
    # linking — an additive field, not a breaking response-shape change.
    accepted_alert_ids: Optional[list[str]] = None
    rejected_alert_ids: Optional[list[str]] = None


class IncidentListResponse(BaseModel):
    total: int
    page: int
    size: int
    pages: int
    incidents: list[IncidentResponse]


class AlertLinkRequest(BaseModel):
    # SS-108: alert_ids (batch) is additive — alert_id (single) is
    # untouched so existing callers keep working exactly as before.
    # Exactly one of the two must be supplied.
    alert_id: Optional[str] = None
    alert_ids: Optional[list[str]] = None

    @model_validator(mode="after")
    def _require_alert_id_or_alert_ids(self) -> "AlertLinkRequest":
        if self.alert_id is None and self.alert_ids is None:
            raise ValueError("Provide either alert_id or alert_ids.")
        return self

    model_config = {
        "json_schema_extra": {
            "example": {"alert_id": "alert-3"},
        }
    }


class IncidentTagsRequest(BaseModel):
    tags: list[str] = Field(default_factory=list)

    model_config = {
        "json_schema_extra": {
            "example": {"tags": ["phishing", "needs-legal-review"]},
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


class TimelineEntry(BaseModel):
    """
    One entry in an incident's investigation timeline (SS-099). `type`
    is one of "alert" / "audit" / "note"; `data` carries the
    type-specific payload — a raw alert dict for "alert" (same shape
    as GET /api/v1/alerts, so the frontend can reuse existing
    alert-rendering components), or a small structured dict for
    "audit"/"note".
    """

    type: str
    timestamp: datetime
    data: dict


class IncidentTimelineResponse(BaseModel):
    incident_id: uuid.UUID
    entries: list[TimelineEntry]
