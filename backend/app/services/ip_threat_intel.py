"""
SafeSOC — IP Threat Intel Lookup
Reads everything ti_cache holds for a set of IPs — the combined verdict
plus each provider's own details and status — for any view that shows
per-IP threat intel (incident Evidence, alert details). One shared
path so those views can't disagree about an IP.
"""

import ipaddress
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import TIDetailStatus, TIProvider
from app.models.ti_cache import TICache
from app.schemas.log import AbuseIPDetails, TIResult, VTIPDetails


class IPThreatIntel(BaseModel):
    """
    Everything ti_cache holds for one IP: the combined verdict plus each
    provider's own details, read only from that provider's row.
    """
    is_malicious: bool
    # Latest real lookup across this IP's rows: each row's
    # result.fetched_at, or its created_at for rows predating fetched_at.
    checked_at: Optional[datetime] = None
    vt: Optional[VTIPDetails] = None
    abuse: Optional[AbuseIPDetails] = None
    vt_status: TIDetailStatus = TIDetailStatus.MISSING
    abuse_status: TIDetailStatus = TIDetailStatus.MISSING


def is_public_ip(ip: str) -> bool:
    """Globally routable — False for private/reserved/documentation ranges and unparseable values."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _cached_result(row: TICache) -> Optional[TIResult]:
    try:
        return TIResult(**(row.result or {}))
    except (TypeError, ValidationError):
        return None


async def get_ip_threat_intel(db: AsyncSession, indicators: list[str]) -> dict[str, IPThreatIntel]:
    """
    Per-IP threat intel from ti_cache. "Checked" means at least one row
    exists for the indicator, from any provider, expired or not — the
    same rule as services/enrichment.py::has_ti_data, so the Evidence
    panel, alert details, and SOAR's ENRICH_INDICATOR never disagree about what was checked.
    """
    if not indicators:
        return {}
    result = await db.execute(select(TICache).where(TICache.indicator.in_(indicators)))
    intel: dict[str, IPThreatIntel] = {}
    for row in result.scalars().all():
        entry = intel.setdefault(row.indicator, IPThreatIntel(is_malicious=False))
        # If any cached provider says malicious, the indicator is
        # malicious; otherwise clean.
        entry.is_malicious = entry.is_malicious or row.is_malicious
        cached = _cached_result(row)
        looked_up_at = (cached.fetched_at if cached is not None else None) or row.created_at
        if looked_up_at is not None and (entry.checked_at is None or looked_up_at > entry.checked_at):
            entry.checked_at = looked_up_at
        if row.provider == TIProvider.VIRUSTOTAL:
            entry.vt = cached.vt if cached is not None else None
            if cached is not None and cached.not_found:
                entry.vt_status = TIDetailStatus.NOT_FOUND
            else:
                entry.vt_status = TIDetailStatus.OK if entry.vt is not None else TIDetailStatus.LEGACY
        elif row.provider == TIProvider.ABUSEIPDB:
            entry.abuse = cached.abuse if cached is not None else None
            entry.abuse_status = TIDetailStatus.OK if entry.abuse is not None else TIDetailStatus.LEGACY
    return intel
