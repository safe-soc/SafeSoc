"""
SafeSOC — Alert Schemas
Response model for alert-level triage actions (SS-107).
"""

import uuid
from datetime import datetime

from pydantic import BaseModel


class AlertAnnotationResponse(BaseModel):
    alert_id: str
    acknowledged: bool
    dismissed: bool
    updated_by_user_id: uuid.UUID
    updated_at: datetime
