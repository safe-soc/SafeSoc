"""
SafeSOC — Shared Audit Log Model
One shared, tenant-scoped audit trail (SS-096, pulling SS-071 forward)
for security-relevant activity across the app — incident actions,
investigation-assistant activity, and any future consumer — rather
than a parallel history table per entity type (see docs/decisions.md
ADR-010). Deliberately generic: target_type/target_id identify what an
entry is about via plain strings rather than a hard per-entity-type
FK, since target ids span multiple systems (Postgres incident UUIDs,
OpenSearch alert string ids, Redis investigation session ids).

Coexists with the existing, narrower IncidentStateTransition for now —
consolidating that into this table is future work (SS-097), not done
by this issue.
"""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, DateTime, ForeignKey, Index, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.models import Base


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    # Nullable: not every audit-worthy event has a human actor (e.g. an
    # incident auto-created by correlation-chain detection).
    actor_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("users.id"), nullable=True)
    # A short, structured identifier — e.g. "incident.created",
    # "incident.status_transitioned", "investigation.query" — not a
    # free-text description. Concrete action names are defined by each
    # future consumer (SS-097/098), not this issue.
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    # What kind of entity this entry is about (e.g. "incident", "alert",
    # "investigation_session") plus its id, as a string — see the
    # module docstring on why this isn't a typed FK.
    target_type: Mapped[str] = mapped_column(String(50), nullable=False)
    target_id: Mapped[str] = mapped_column(String(255), nullable=False)
    # Structured, action-specific metadata (e.g. {"from_status": "open",
    # "to_status": "investigating"}) — shape varies per action type,
    # same JSON-column pattern already used for Incident.alert_ids.
    details: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (
        # The two access patterns this table exists to serve: "everything
        # that happened to entity X" and "recent activity for tenant Y".
        Index("ix_audit_log_tenant_target", "tenant_id", "target_type", "target_id"),
        Index("ix_audit_log_tenant_created", "tenant_id", "created_at"),
    )
