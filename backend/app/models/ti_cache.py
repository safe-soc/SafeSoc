"""
SafeSOC — Threat Intel Cache Model
Cache-before-call TTL cache for TI provider lookups (SRS §3.3): 7-day
TTL for malicious indicators, 24h for clean, both read from config.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import JSON, Boolean, DateTime, UniqueConstraint, func
from sqlalchemy import Enum as SAEnum
from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.config import settings
from app.core.enums import TIProvider
from app.models import Base


class TICache(Base):
    __tablename__ = "ti_cache"
    __table_args__ = (
        UniqueConstraint("indicator", "provider", name="uq_ti_cache_indicator_provider"),
    )

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    indicator: Mapped[str] = mapped_column(String(512), nullable=False)
    provider: Mapped[TIProvider] = mapped_column(
        SAEnum(TIProvider, name="ti_provider", values_callable=lambda enum_cls: [m.value for m in enum_cls]),
        nullable=False,
    )
    result: Mapped[dict] = mapped_column(JSON, nullable=False)
    is_malicious: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


def compute_expiry(is_malicious: bool, *, now: Optional[datetime] = None) -> datetime:
    """
    Compute a ti_cache row's expires_at per SRS §3.3: 7-day TTL for
    malicious indicators, 24h for clean, both read from
    settings.TI_CACHE_MALICIOUS_TTL/TI_CACHE_CLEAN_TTL rather than
    hardcoded here.
    """
    now = now or datetime.now(timezone.utc)
    ttl_seconds = settings.TI_CACHE_MALICIOUS_TTL if is_malicious else settings.TI_CACHE_CLEAN_TTL
    return now + timedelta(seconds=ttl_seconds)
