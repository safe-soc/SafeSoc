"""
SafeSOC — Alert Schemas
Request/response models for alert-level triage actions (SS-107):
acknowledge, dismiss (with a reason) and restore.
"""

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, model_validator

from app.core.enums import DismissReason
from app.models.alert_annotation import DISMISS_NOTE_MAX_LENGTH


class AlertDismissRequest(BaseModel):
    reason: DismissReason
    note: Optional[str] = Field(None, max_length=DISMISS_NOTE_MAX_LENGTH)

    @model_validator(mode="after")
    def _note_required_for_other(self) -> "AlertDismissRequest":
        # Blank/whitespace-only notes are stored as null, not "".
        self.note = (self.note or "").strip() or None
        if self.reason == DismissReason.OTHER and self.note is None:
            raise ValueError('A note is required when the reason is "other".')
        return self

    model_config = {
        "json_schema_extra": {
            "example": {"reason": "expected_activity", "note": "Nightly backup job on this host."},
        }
    }


class AlertAnnotationResponse(BaseModel):
    alert_id: str
    acknowledged: bool
    dismissed: bool
    dismiss_reason: Optional[DismissReason] = None
    dismiss_note: Optional[str] = None
    updated_by_user_id: uuid.UUID
    updated_at: datetime
