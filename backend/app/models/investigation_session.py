"""
SafeSOC — Investigation Session Models
Persistent, incident-scoped investigation memory: a session groups a
conversation (InvestigationTurn), structured findings
(InvestigationFinding), concrete follow-up actions
(InvestigationAction), and free-form analyst commentary
(InvestigationNote) — replacing the old approach of relying purely on
an ephemeral, Redis-backed chat transcript (services/investigation.py,
still used unchanged for the general, non-incident-scoped Investigate
page) for anything an analyst needs to still see days later.

Tenant scoping follows IncidentNote's own precedent exactly (see
models/incident.py): no tenant_id column on any table here. Every
query is reached only through an already tenant-verified Incident row
(services/incidents.py:get_incident, 404-for-both-missing-and-not-yours)
and then filtered by incident_id/session_id — see
services/investigation_session.py's own docstring for why a session_id
alone is never enough to reach these rows.

InvestigationFinding.category vs InvestigationAction is a deliberate
split, not an oversight: a finding's `open_question` category is
something not yet KNOWN ("what was the initial access vector?"); an
action is something an analyst should DO ("pull DNS logs for
DEMO-CRITICAL-01"). Conflating the two into one table was considered
and rejected — the two need different lifecycle fields (a finding
tracks who/when it was *confirmed*; an action tracks who/when it was
*completed*), and blending them would leave one set of columns always
null depending on which kind a row represents.
"""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Text, func
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import FindingCategory, FindingOrigin, InvestigationActionStatus
from app.models import Base

_FINDING_CATEGORY_TYPE = SAEnum(
    FindingCategory, name="investigation_finding_category", values_callable=lambda enum_cls: [m.value for m in enum_cls]
)
_FINDING_ORIGIN_TYPE = SAEnum(
    FindingOrigin, name="investigation_finding_origin", values_callable=lambda enum_cls: [m.value for m in enum_cls]
)
_ACTION_STATUS_TYPE = SAEnum(
    InvestigationActionStatus, name="investigation_action_status", values_callable=lambda enum_cls: [m.value for m in enum_cls]
)


class InvestigationSession(Base):
    """
    One investigation session for one incident. Multiple sessions per
    incident are allowed on purpose (Phase 3: "New investigation"
    starts clean, past sessions stay in history) — "the current one"
    is simply the most recently created, not a stored flag.
    """

    __tablename__ = "investigation_sessions"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id"), nullable=False)
    created_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    turns: Mapped[list["InvestigationTurn"]] = relationship(back_populates="session", order_by="InvestigationTurn.created_at")
    findings: Mapped[list["InvestigationFinding"]] = relationship(back_populates="session", order_by="InvestigationFinding.created_at")
    actions: Mapped[list["InvestigationAction"]] = relationship(back_populates="session", order_by="InvestigationAction.created_at")
    notes: Mapped[list["InvestigationNote"]] = relationship(back_populates="session", order_by="InvestigationNote.created_at")


class InvestigationTurn(Base):
    """
    One (question, answer) pair — mirrors services/investigation.py's
    own ConversationContext.transcript shape (`{"query":..., "answer":...}`)
    and investigate.py's prompt-building expectations, just persisted
    instead of TTL'd in Redis.
    """

    __tablename__ = "investigation_turns"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("investigation_sessions.id"), nullable=False)
    asked_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    question: Mapped[str] = mapped_column(Text, nullable=False)
    answer: Mapped[str] = mapped_column(Text, nullable=False)
    # Mirrors IncidentNarrativeResponse.is_fallback/InvestigateResponse.is_fallback
    # — True when `answer` is the deterministic fallback, not a genuine LLM response.
    is_fallback: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    session: Mapped["InvestigationSession"] = relationship(back_populates="turns")


class InvestigationFinding(Base):
    """
    A structured finding at one of three certainty levels
    (FindingCategory). `origin` records who proposed it — the AI path
    (services/investigation_session.py) can only ever write
    origin=ai_suggested and category in (hypothesis, open_question);
    category=confirmed and confirmed_by_user_id/confirmed_at are set
    exclusively by an explicit analyst PATCH, never automatically.
    """

    __tablename__ = "investigation_findings"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("investigation_sessions.id"), nullable=False)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[FindingCategory] = mapped_column(_FINDING_CATEGORY_TYPE, nullable=False)
    origin: Mapped[FindingOrigin] = mapped_column(_FINDING_ORIGIN_TYPE, nullable=False)
    created_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("users.id"), nullable=True)
    confirmed_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("users.id"), nullable=True)
    confirmed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    session: Mapped["InvestigationSession"] = relationship(back_populates="findings")


class InvestigationAction(Base):
    """A concrete follow-up action an analyst should take — distinct from a finding's open_question (see module docstring)."""

    __tablename__ = "investigation_actions"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("investigation_sessions.id"), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[InvestigationActionStatus] = mapped_column(_ACTION_STATUS_TYPE, nullable=False, default=InvestigationActionStatus.OPEN)
    created_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    completed_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("users.id"), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    session: Mapped["InvestigationSession"] = relationship(back_populates="actions")


class InvestigationNote(Base):
    """Free-form analyst commentary — same shape as IncidentNote, scoped to a session instead of directly to an incident."""

    __tablename__ = "investigation_notes"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("investigation_sessions.id"), nullable=False)
    author_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    session: Mapped["InvestigationSession"] = relationship(back_populates="notes")
