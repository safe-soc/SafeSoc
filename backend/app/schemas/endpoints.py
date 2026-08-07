"""
SafeSOC — Endpoint Schemas
Response model for the endpoints listing API (SS-034).
"""

import uuid
from datetime import datetime

from pydantic import BaseModel

from app.core.enums import RiskLevel


class EndpointResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    host_id: str
    risk_score: int
    risk_level: RiskLevel
    updated_at: datetime
