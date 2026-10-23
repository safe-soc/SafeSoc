"""
SafeSOC — Investigation Schemas
Request/response models for the natural-language investigation
endpoint (SS-047).
"""

from typing import Optional

from pydantic import BaseModel

from app.core.enums import FallbackReason, Intent


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
    # True whenever `answer` is a deterministic templated/explanatory
    # summary rather than a genuine LLM-generated response — an LLM
    # timeout/failure (SS-047) or a failed tool call (SS-085). Defaults
    # to False so existing callers that don't set it explicitly still
    # get correct semantics (SS-084).
    is_fallback: bool = False
    # Why it's a fallback, when it is: the LLM was rate limited (the UI
    # says "AI busy"), timed out, errored, cited a number not in the data
    # (ungrounded), or the data itself couldn't be retrieved (data_error).
    fallback_reason: Optional[FallbackReason] = None
