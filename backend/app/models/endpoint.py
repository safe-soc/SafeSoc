"""
SafeSOC — Endpoint Model
A known host (tenant_id + host_id), with its most recently computed
risk score/level (SS-032). Rows are upserted by the periodic risk
recalculation task (SS-033), not created directly by ingestion — a
host becomes "known" the first time its score is computed.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint, func
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import RiskLevel
from app.models import Base


class Endpoint(Base):
    __tablename__ = "endpoints"
    __table_args__ = (
        UniqueConstraint("tenant_id", "host_id", name="uq_endpoints_tenant_id_host_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    host_id: Mapped[str] = mapped_column(String(255), nullable=False)
    risk_score: Mapped[int] = mapped_column(nullable=False, default=0)
    risk_level: Mapped[RiskLevel] = mapped_column(
        SAEnum(RiskLevel, name="risk_level", values_callable=lambda enum_cls: [member.value for member in enum_cls]),
        nullable=False,
        default=RiskLevel.LOW,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
