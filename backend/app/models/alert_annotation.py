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

from sqlalchemy import Boolean, DateTime, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.models import Base


class AlertAnnotation(Base):
    __tablename__ = "alert_annotations"
    __table_args__ = (UniqueConstraint("tenant_id", "alert_id", name="uq_alert_annotations_tenant_id_alert_id"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    alert_id: Mapped[str] = mapped_column(String(255), nullable=False)
    acknowledged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    dismissed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    updated_by_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
