"""
SafeSOC — Incident Model
An incident tracks a security event worth investigating: status,
linked alert_ids, assigned analyst, and an append-only audit trail of
every state transition (timestamp + acting user) per SRS §3.3.

SS-035 note: this is a dependency pull-forward from Milestone 7,
implemented specifically to unblock SS-031 (Milestone 6). Scope is
strictly the schema — creation/transition orchestration logic
(the actual CRUD/lifecycle endpoints) is SS-036, not built here.
"""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Text, func
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import CorrelationPattern, IncidentStatus
from app.models import Base

# Shared enum type object — reused across every status column below so
# Alembic/SQLAlchemy treat them as one Postgres enum type (incident_status),
# not a separately-created type per column.
_INCIDENT_STATUS_TYPE = SAEnum(
    IncidentStatus, name="incident_status", values_callable=lambda enum_cls: [m.value for m in enum_cls]
)

# SS-094: same pattern, for the incident's category column below —
# reuses the correlation engine's own CorrelationPattern vocabulary
# (core/enums.py) rather than inventing a parallel one.
_INCIDENT_CATEGORY_TYPE = SAEnum(
    CorrelationPattern, name="incident_category", values_callable=lambda enum_cls: [m.value for m in enum_cls]
)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    status: Mapped[IncidentStatus] = mapped_column(_INCIDENT_STATUS_TYPE, nullable=False, default=IncidentStatus.OPEN)
    alert_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    assigned_analyst_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("users.id"), nullable=True)
    # SS-094: populated from the DetectedChain that created/last merged
    # into this incident (services/incidents.py) — both already computed
    # by the correlation engine at detection time, previously discarded
    # after the Telegram notification was sent. Null for manually-created
    # incidents (services/incidents.py:create_incident), which have no
    # detected chain to draw them from. Deliberately does NOT add a
    # `severity` field here too — unlike category/confidence, deriving
    # one would require a new OpenSearch lookup of the linked alerts at
    # incident-creation time, a real scope/latency addition beyond a
    # data-model extension, not just wiring through data already at hand.
    category: Mapped[Optional[CorrelationPattern]] = mapped_column(_INCIDENT_CATEGORY_TYPE, nullable=True)
    confidence: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    # SS-106: free-form analyst-authored labels (e.g. "phishing",
    # "needs-legal-review") — distinct from `category`, which is the
    # correlation engine's own fixed vocabulary set at detection time.
    tags: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    transitions: Mapped[list["IncidentStateTransition"]] = relationship(
        back_populates="incident", order_by="IncidentStateTransition.created_at"
    )
    notes: Mapped[list["IncidentNote"]] = relationship(back_populates="incident", order_by="IncidentNote.created_at")


class IncidentStateTransition(Base):
    """
    One row per status change (including the initial creation, recorded
    as from_status=None -> to_status=OPEN) — an append-only audit log,
    never updated or deleted, satisfying "every state transition is
    recorded with timestamp + acting user."
    """

    __tablename__ = "incident_state_transitions"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id"), nullable=False)
    from_status: Mapped[Optional[IncidentStatus]] = mapped_column(_INCIDENT_STATUS_TYPE, nullable=True)
    to_status: Mapped[IncidentStatus] = mapped_column(_INCIDENT_STATUS_TYPE, nullable=False)
    changed_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    incident: Mapped["Incident"] = relationship(back_populates="transitions")


class IncidentNote(Base):
    """
    A timestamped analyst note attached to an incident (SS-037), per
    SRS §3.3. Append-only: no update or delete path is exposed anywhere
    — once posted, a note is immutable.
    """

    __tablename__ = "incident_notes"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id"), nullable=False)
    author_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    incident: Mapped["Incident"] = relationship(back_populates="notes")
