"""
SafeSOC — Investigation Schemas
Request/response models for the natural-language investigation
endpoint (SS-047).
"""

from typing import Optional

from pydantic import BaseModel

from app.core.enums import Intent


class InvestigateRequest(BaseModel):
    query: str
    session_id: Optional[str] = None

    model_config = {
        "json_schema_extra": {
            "example": {"query": "Show me failed logins for host DESKTOP-042", "session_id": None},
        }
    }


class InvestigateResponse(BaseModel):
    session_id: str
    intent: Intent
    answer: str
    data: dict
