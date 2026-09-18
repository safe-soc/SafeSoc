"""
SafeSOC — Endpoint Software Inventory Model
Demonstration-level software inventory + vulnerability layer for the
endpoint detail page. No such model existed before this — the
smallest clean representation that supports "what's installed on this
host, and what's known-vulnerable about it": one row per (host,
software), with any known vulnerabilities as a JSON list on that row
(the same JSON-column-for-structured-sub-data convention already used
by Incident.alert_ids/tags), rather than a second table + relationship
for what is, at this scale, always fetched and rendered together.

Not tied to Endpoint by a foreign key: a host can have software rows
before it's ever been risk-scored (Endpoint rows are created lazily by
the scoring task, same as evidence/graph code elsewhere in this
codebase already treats host_id as a plain string join key rather than
requiring an Endpoint row to exist first).
"""

import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, String, UniqueConstraint, func
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import SoftwareCategory
from app.models import Base


class EndpointSoftware(Base):
    __tablename__ = "endpoint_software"
    __table_args__ = (
        UniqueConstraint("tenant_id", "host_id", "name", name="uq_endpoint_software_tenant_host_name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    host_id: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    category: Mapped[SoftwareCategory] = mapped_column(
        SAEnum(SoftwareCategory, name="software_category", values_callable=lambda enum_cls: [m.value for m in enum_cls]),
        nullable=False,
    )
    # list[{"id": str, "severity": str, "title": str, "is_synthetic": bool}].
    # `id` is a real CVE only when genuinely known for this exact
    # software+version; otherwise a clearly-labeled "DEMO-VULN-####" id
    # with is_synthetic=True — see injector/simulate.py's own
    # VULNERABILITY_CATALOG for the sourcing rule. Empty list = no known
    # vulnerabilities for this software.
    vulnerabilities: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
