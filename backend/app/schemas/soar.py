"""
SafeSOC — SOAR Schemas
Two things live here: (1) the per-action-type parameter validation
models — the ONLY path raw parameters may take on their way into
SoarActionExecution.parameters (see services/soar.py::
validate_action_parameters) — and (2) the read-only response shapes
for GET /api/v1/soar/playbooks and
GET /api/v1/incidents/{id}/soar/runs[/{run_id}].
"""

import ipaddress
import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, field_validator

from app.core.enums import (
    AutonomyClass,
    CorrelationPattern,
    RecommendationSource,
    SoarActionStatus,
    SoarActionType,
    SoarRunStatus,
    SoarTriggerSource,
    SoarVerificationStatus,
)

# ── Per-action-type parameter validation ───────────────────────────
#
# Every field here is a plain, typed value — never a template string,
# never anything evaluated. See core/soar_playbooks.py's module
# docstring for why parameters can only ever come from a fixed set of
# resolved evidence fields plus small static literals.

_DANGEROUS_TOKENS = (";", "|", "&", "`", "$(", "\n", "\r")


def _reject_dangerous_characters(value: str, field_name: str) -> str:
    if any(token in value for token in _DANGEROUS_TOKENS):
        raise ValueError(f"{field_name} contains a disallowed character.")
    return value


class IsolateEndpointParams(BaseModel):
    host_id: str


class TerminateProcessParams(BaseModel):
    host_id: str
    process: Optional[str] = None


class DisableAccountParams(BaseModel):
    user: str


class RevokeCredentialsParams(BaseModel):
    user: str


class BlockIndicatorParams(BaseModel):
    indicator: str

    @field_validator("indicator")
    @classmethod
    def _validate_indicator(cls, value: str) -> str:
        """Must be a syntactically valid IP address or a plausible, metacharacter-free domain — never passed through unchecked."""
        value = value.strip()
        if not value:
            raise ValueError("indicator must not be empty.")
        try:
            ipaddress.ip_address(value)
            return value
        except ValueError:
            pass
        if " " in value or "." not in value:
            raise ValueError("indicator must be a valid IP address or domain.")
        return _reject_dangerous_characters(value, "indicator")


class EnrichIndicatorParams(BaseModel):
    indicator: str


class CollectAdditionalEvidenceParams(BaseModel):
    host_id: Optional[str] = None


class CreateInvestigationActionParams(BaseModel):
    description: str


class AddIncidentNoteParams(BaseModel):
    note: str


class IncreaseIncidentPriorityParams(BaseModel):
    reason: Optional[str] = None


# Every SoarActionType MUST have exactly one entry here — see
# services/soar.py::validate_action_parameters, which does a direct
# dict lookup with no fallback.
ACTION_PARAMETER_MODELS: dict[SoarActionType, type[BaseModel]] = {
    SoarActionType.COLLECT_ADDITIONAL_EVIDENCE: CollectAdditionalEvidenceParams,
    SoarActionType.CREATE_INVESTIGATION_ACTION: CreateInvestigationActionParams,
    SoarActionType.ENRICH_INDICATOR: EnrichIndicatorParams,
    SoarActionType.ADD_INCIDENT_NOTE: AddIncidentNoteParams,
    SoarActionType.INCREASE_INCIDENT_PRIORITY: IncreaseIncidentPriorityParams,
    SoarActionType.ISOLATE_ENDPOINT: IsolateEndpointParams,
    SoarActionType.DISABLE_ACCOUNT: DisableAccountParams,
    SoarActionType.BLOCK_INDICATOR: BlockIndicatorParams,
    SoarActionType.TERMINATE_PROCESS: TerminateProcessParams,
    SoarActionType.REVOKE_CREDENTIALS: RevokeCredentialsParams,
}


# ── Read-only response shapes ───────────────────────────────────────

class PlaybookStepResponse(BaseModel):
    action_type: SoarActionType
    parameter_field: str
    static_parameters: dict


class PlaybookResponse(BaseModel):
    id: str
    title: str
    trigger_pattern: CorrelationPattern
    trigger_min_confidence: float
    steps: list[PlaybookStepResponse]


class SoarActionExecutionResponse(BaseModel):
    id: uuid.UUID
    action_type: SoarActionType
    parameters: dict
    autonomy_class: AutonomyClass
    recommended_by: RecommendationSource
    status: SoarActionStatus
    approved_by_user_id: Optional[uuid.UUID] = None
    approved_at: Optional[datetime] = None
    # Phase 3 — a separate identity/timestamp pair from approved_by_user_id/
    # approved_at (see models/soar.py's own comment on why): an action
    # is only ever approved OR rejected, so exactly one of these two
    # pairs is ever populated, never both.
    rejected_by_user_id: Optional[uuid.UUID] = None
    rejected_at: Optional[datetime] = None
    decision_reason: Optional[str] = None
    executed_at: Optional[datetime] = None
    result: Optional[dict] = None
    verification_status: SoarVerificationStatus
    verified_at: Optional[datetime] = None
    created_at: datetime


class SoarPlaybookRunSummary(BaseModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    playbook_id: str
    triggered_by: SoarTriggerSource
    status: SoarRunStatus
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime


class SoarPlaybookRunDetail(SoarPlaybookRunSummary):
    actions: list[SoarActionExecutionResponse]


class ApprovalDecisionRequest(BaseModel):
    """Optional analyst reasoning for either an approve or a reject decision — POST body for both endpoints (routers/v1/soar.py)."""
    reason: Optional[str] = None
