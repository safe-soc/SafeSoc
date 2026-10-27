"""
SafeSOC — Threat Intel Refresh
Analyst-requested re-lookup of one incident evidence IP against every
TI provider. Validates and tenant-scopes the request here, applies a
short per-IP cooldown, and hands the actual lookup to the Celery worker
(tasks/enrichment.py::refresh_indicator) — the provider clients block
(VirusTotal's rate limiter sleeps up to 60s), so they never run inside
a request handler.
"""

import ipaddress
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import IndicatorNotInIncidentError, InvalidIndicatorError, ThreatIntelRefreshCooldownError
from app.db.redis import get_client
from app.services.audit import record_event
from app.services.incident_evidence import get_incident_evidence
from app.tasks.enrichment import refresh_indicator
from app.utils.logger import get_logger

logger = get_logger(__name__)

REFRESH_COOLDOWN_SECONDS = 60


def _validate_public_ip(ip: str) -> str:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        raise InvalidIndicatorError(ip) from None
    if not parsed.is_global:
        raise InvalidIndicatorError(ip)
    return str(parsed)


def _normalize(ip: str) -> str | None:
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return None


async def _claim_cooldown(ip: str) -> bool:
    """
    True if this caller won the cooldown slot. ti_cache is global, so
    the key is per-IP, not per-tenant. Fails open on a Redis outage,
    same reasoning as services/rate_limit.py — the worker's own provider
    rate limiters still bound the real API usage.
    """
    try:
        return bool(await get_client().set(f"ti_refresh:{ip}", "1", nx=True, ex=REFRESH_COOLDOWN_SECONDS))
    except Exception as e:
        logger.warning("TI refresh cooldown unavailable, allowing request", ip=ip, error=str(e))
        return True


async def request_ip_refresh(
    db: AsyncSession, tenant_id: uuid.UUID, incident_id: uuid.UUID, ip: str, actor_user_id: uuid.UUID
) -> str:
    """
    Queue a forced TI refresh for an incident's evidence IP; returns the
    IP as it appears in the incident's evidence.

    Raises:
        InvalidIndicatorError: (400) not a valid, globally routable IP.
        IncidentNotFoundError: (404) via get_incident_evidence — also
        covers another tenant's incident.
        IndicatorNotInIncidentError: (404) IP not among the incident's evidence.
        ThreatIntelRefreshCooldownError: (429) refreshed within the cooldown.
    """
    normalized = _validate_public_ip(ip)
    evidence = await get_incident_evidence(db, tenant_id, incident_id)
    # Compare normalized forms, but keep the evidence's own spelling —
    # it's the ti_cache key the refresh has to overwrite.
    match = next((entity.ip for entity in evidence.ips if _normalize(entity.ip) == normalized), None)
    if match is None:
        raise IndicatorNotInIncidentError(ip)
    ip = match

    if not await _claim_cooldown(ip):
        raise ThreatIntelRefreshCooldownError()

    refresh_indicator.delay(ip)

    try:
        await record_event(
            db, tenant_id, action="threat_intel.refresh_requested", target_type="incident",
            target_id=str(incident_id), actor_user_id=actor_user_id, details={"ip": ip},
        )
    except Exception as e:
        logger.warning("Audit logging failed for TI refresh request", ip=ip, error_type=type(e).__name__, error=str(e))

    return ip
