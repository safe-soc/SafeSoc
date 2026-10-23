"""
SafeSOC — Alert Annotation Model
Lightweight Postgres side-table for per-tenant analyst triage state on
an OpenSearch-indexed alert (SS-107): acknowledged/dismissed flags plus
who last changed them. Deliberately NOT a mutation of the alert
document itself — ingested alert documents stay append-clean (the same
append-only reasoning db/opensearch.py's update_alert_ti_fields/
update_alert_anomaly_score already stretch for enrichment fields
doesn't extend to analyst-authored triage state, which belongs in
Postgres alongside the rest of this app's mutable, relational state).
"""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import DismissReason
from app.models import Base

DISMISS_NOTE_MAX_LENGTH = 500

# Stored as plain text (VARCHAR, no Postgres enum type and no CHECK
# constraint), so adding a reason later needs no migration; values are
# validated by the DismissRequest schema before they get here.
_DISMISS_REASON_TYPE = Enum(
    DismissReason, native_enum=False, create_constraint=False, length=32,
    values_callable=lambda enum_cls: [m.value for m in enum_cls],
)


class AlertAnnotation(Base):
    __tablename__ = "alert_annotations"
    __table_args__ = (UniqueConstraint("tenant_id", "alert_id", name="uq_alert_annotations_tenant_id_alert_id"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    alert_id: Mapped[str] = mapped_column(String(255), nullable=False)
    acknowledged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    dismissed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Why it was dismissed, and an optional free-text note (required by
    # the API when the reason is "other"). Both null unless dismissed;
    # restoring the alert clears them.
    dismiss_reason: Mapped[Optional[DismissReason]] = mapped_column(_DISMISS_REASON_TYPE, nullable=True)
    dismiss_note: Mapped[Optional[str]] = mapped_column(String(DISMISS_NOTE_MAX_LENGTH), nullable=True)
    updated_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
