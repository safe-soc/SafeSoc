"""
SafeSOC — SOAR Playbook Execution Models
A SoarPlaybookRun is one playbook's execution against one incident;
each of its steps becomes a SoarActionExecution row. Together these
are the minimum genuinely-new persistence the SOAR feature needs —
everything static (which playbooks exist, what their steps are, which
actions are AUTOMATIC vs APPROVAL_REQUIRED) lives in core/
soar_playbooks.py / core/soar_policy.py instead, not here.

Tenant scoping follows InvestigationSession's own precedent exactly
(models/investigation_session.py): no tenant_id column on either
table. Every query is reached only through an already tenant-verified
Incident row (services/incidents.py:get_incident) and then filtered by
incident_id/run_id — see services/soar.py's own docstring for why a
run_id alone is never enough to reach a run.

autonomy_class is a SNAPSHOT of core/soar_policy.py::classify() taken
at the moment a SoarActionExecution is created, not a live lookup — a
later change to ACTION_AUTONOMY must never retroactively alter what an
already-created action was permitted to do (audit integrity).
"""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, DateTime, ForeignKey, String, Text, func
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import (
    AutonomyClass,
    RecommendationSource,
    SoarActionStatus,
    SoarActionType,
    SoarRunStatus,
    SoarTriggerSource,
    SoarVerificationStatus,
)
from app.models import Base

_RUN_STATUS_TYPE = SAEnum(SoarRunStatus, name="soar_run_status", values_callable=lambda enum_cls: [m.value for m in enum_cls])
_TRIGGER_SOURCE_TYPE = SAEnum(SoarTriggerSource, name="soar_trigger_source", values_callable=lambda enum_cls: [m.value for m in enum_cls])
_ACTION_TYPE_TYPE = SAEnum(SoarActionType, name="soar_action_type", values_callable=lambda enum_cls: [m.value for m in enum_cls])
_AUTONOMY_CLASS_TYPE = SAEnum(AutonomyClass, name="soar_autonomy_class", values_callable=lambda enum_cls: [m.value for m in enum_cls])
_RECOMMENDATION_SOURCE_TYPE = SAEnum(
    RecommendationSource, name="soar_recommendation_source", values_callable=lambda enum_cls: [m.value for m in enum_cls]
)
_ACTION_STATUS_TYPE = SAEnum(SoarActionStatus, name="soar_action_status", values_callable=lambda enum_cls: [m.value for m in enum_cls])
_VERIFICATION_STATUS_TYPE = SAEnum(
    SoarVerificationStatus, name="soar_verification_status", values_callable=lambda enum_cls: [m.value for m in enum_cls]
)


class SoarPlaybookRun(Base):
    __tablename__ = "soar_playbook_runs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id"), nullable=False)
    # References core/soar_playbooks.py's static Playbook.id (e.g.
    # "pb-successful-compromise") — not a FK, same convention as
    # Compliance's requirement.id: the playbook catalog isn't a table.
    playbook_id: Mapped[str] = mapped_column(String(100), nullable=False)
    triggered_by: Mapped[SoarTriggerSource] = mapped_column(_TRIGGER_SOURCE_TYPE, nullable=False)
    status: Mapped[SoarRunStatus] = mapped_column(_RUN_STATUS_TYPE, nullable=False, default=SoarRunStatus.PENDING)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    actions: Mapped[list["SoarActionExecution"]] = relationship(
        back_populates="playbook_run", order_by="SoarActionExecution.created_at"
    )


class SoarActionExecution(Base):
    __tablename__ = "soar_action_executions"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    playbook_run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("soar_playbook_runs.id"), nullable=False)
    action_type: Mapped[SoarActionType] = mapped_column(_ACTION_TYPE_TYPE, nullable=False)
    # Validated against app/schemas/soar.py's per-action-type Pydantic
    # model BEFORE this row is ever created — see
    # services/soar.py::validate_action_parameters. Never a raw,
    # unvalidated dict.
    parameters: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    autonomy_class: Mapped[AutonomyClass] = mapped_column(_AUTONOMY_CLASS_TYPE, nullable=False)
    recommended_by: Mapped[RecommendationSource] = mapped_column(_RECOMMENDATION_SOURCE_TYPE, nullable=False)
    status: Mapped[SoarActionStatus] = mapped_column(_ACTION_STATUS_TYPE, nullable=False, default=SoarActionStatus.PENDING)
    # Set ONLY by an explicit analyst approval action (Phase 2) — mirrors
    # InvestigationFinding.confirmed_by_user_id exactly: the AI/playbook
    # path can never set these itself.
    approved_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("users.id"), nullable=True)
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # Phase 3: set ONLY by an explicit analyst rejection (services/
    # soar.py::reject_action) — a separate identity/timestamp pair from
    # approved_by_user_id/approved_at, not a reuse of those columns,
    # since an action is only ever approved OR rejected and a field
    # literally named "approved_by" holding a rejector's id would be
    # actively misleading to anyone reading this row or the API
    # response built from it.
    rejected_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("users.id"), nullable=True)
    rejected_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # Phase 3: the analyst's optional free-text reason for either
    # decision — shared by approve and reject (never both set, since a
    # given action is only ever approved or rejected once).
    decision_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    executed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    result: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    verification_status: Mapped[SoarVerificationStatus] = mapped_column(
        _VERIFICATION_STATUS_TYPE, nullable=False, default=SoarVerificationStatus.NOT_VERIFIED
    )
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    playbook_run: Mapped["SoarPlaybookRun"] = relationship(back_populates="actions")
