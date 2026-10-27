"""
SafeSOC — Threat Intel Enrichment Service
Given a NormalizedLog with an IP or file-hash indicator, checks
ti_cache first (SS-024), calls the matching client(s) (SS-022/023) on
a miss, writes the result back to the cache and to the OpenSearch
document's ti_result/ti_enriched/risk_score fields (SRS §3.3/§3.4).
"""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.clients import abuseipdb, virustotal
from app.clients.abuseipdb import AbuseIPDBError
from app.clients.virustotal import VirusTotalError
from app.core.config import settings
from app.core.enums import TIProvider
from app.db.opensearch import update_alert_ti_fields
from app.models.ti_cache import TICache, compute_expiry
from app.schemas.log import NormalizedLog, TIResult
from app.utils.logger import get_logger

logger = get_logger(__name__)


async def _get_cached(db: AsyncSession, indicator: str, provider: TIProvider) -> Optional[TICache]:
    result = await db.execute(
        select(TICache).where(TICache.indicator == indicator, TICache.provider == provider)
    )
    return result.scalar_one_or_none()


async def has_ti_data(db: AsyncSession, indicator: str) -> bool:
    """
    Whether any TI provider has ever checked this indicator — i.e. at
    least one ti_cache row exists for it, from any provider, expired or
    not.

    This is deliberately the SAME definition of "checked" that
    services/incident_evidence.py::_ti_intel uses to decide between
    a verdict and "Not checked" in the Evidence panel, so callers
    reporting enrichment coverage agree with what that panel shows.
    Note what it is NOT: a verdict-value test. A clean indicator that a
    provider really did check carries all-zero counters, which is
    indistinguishable by value from "nothing answered" — only the
    presence of a cache row separates the two.
    """
    result = await db.execute(select(TICache.id).where(TICache.indicator == indicator).limit(1))
    return result.first() is not None


async def _write_cache(db: AsyncSession, indicator: str, provider: TIProvider, result: TIResult) -> None:
    existing = await _get_cached(db, indicator, provider)
    expires_at = compute_expiry(result.is_malicious)
    if existing is not None:
        existing.result = result.model_dump(mode="json")
        existing.is_malicious = result.is_malicious
        existing.expires_at = expires_at
    else:
        db.add(TICache(
            indicator=indicator,
            provider=provider,
            result=result.model_dump(mode="json"),
            is_malicious=result.is_malicious,
            expires_at=expires_at,
        ))
    await db.commit()


async def _get_or_fetch(db, indicator, provider, fetch_fn) -> Optional[TIResult]:
    """
    Cache-before-call for a single (indicator, provider) pair.

    Falls back to a stale cached result (SRS §3.4) if the live call
    fails and a cache row exists at all, even expired; if there's
    truly nothing cached, returns None (no-op for this provider) —
    an external API outage never raises past this point.

    The provider call is made with NO database transaction open. The
    cache read above opens one implicitly, and leaving it open across
    the HTTP request pinned a Postgres backend `idle in transaction`
    for the whole of the provider's latency — measured at 13-23s under
    load, against providers that are slow or unreachable precisely when
    the system is busiest. Committing first ends that transaction and
    releases the connection; _write_cache then opens a short new one
    only if there is something to persist.

    The commit is deliberate and matches what this module already did:
    _write_cache has always committed the caller's session on this same
    cache-miss path. Ending the transaction earlier keeps that
    behaviour and only moves the boundary — a rollback here would
    instead DISCARD any caller work in flight, which would be a real
    change. The cache-hit path below returns before this point and is
    left exactly as it was: it makes no HTTP call, so it has no
    boundary to fix.
    """
    cached_row = await _get_cached(db, indicator, provider)
    now = datetime.now(timezone.utc)
    if cached_row is not None and cached_row.expires_at > now:
        return TIResult(**cached_row.result)

    # Read what the fallback needs off the ORM row before ending the
    # transaction it was loaded in, so nothing has to touch the
    # database again once the connection is released.
    stale_result = dict(cached_row.result) if cached_row is not None else None

    await db.commit()

    try:
        result = await fetch_fn()
    except (VirusTotalError, AbuseIPDBError) as e:
        logger.warning(
            "TI provider lookup failed, falling back",
            provider=provider.value, indicator=indicator, error=str(e),
        )
        if stale_result is not None:
            return TIResult(**stale_result)
        return None

    await _write_cache(db, indicator, provider, result)
    return result


def _merge(
    *,
    source_ip: Optional[str] = None,
    file_hash: Optional[str] = None,
    vt: Optional[TIResult],
    abuse: Optional[TIResult],
) -> TIResult:
    vt = vt or TIResult()
    abuse = abuse or TIResult()
    return TIResult(
        source_ip=source_ip,
        file_hash=file_hash,
        vt_malicious=vt.vt_malicious,
        vt_total=vt.vt_total,
        abuse_confidence=abuse.abuse_confidence,
        abuse_total_reports=abuse.abuse_total_reports,
        is_malicious=vt.is_malicious or abuse.is_malicious,
        # Each provider's details come only from its own result, so
        # neither can blank the other out.
        vt=vt.vt,
        abuse=abuse.abuse,
    )


async def _get_ip_result(db: AsyncSession, ip: str) -> TIResult:
    vt = await _get_or_fetch(db, ip, TIProvider.VIRUSTOTAL, lambda: virustotal.lookup_ip(ip))
    abuse = await _get_or_fetch(db, ip, TIProvider.ABUSEIPDB, lambda: abuseipdb.lookup_ip(ip))
    return _merge(source_ip=ip, vt=vt, abuse=abuse)


async def _get_hash_result(db: AsyncSession, file_hash: str) -> TIResult:
    vt = await _get_or_fetch(db, file_hash, TIProvider.VIRUSTOTAL, lambda: virustotal.lookup_hash(file_hash))
    return _merge(file_hash=file_hash, vt=vt, abuse=None)


async def enrich_indicator(db: AsyncSession, indicator: str) -> TIResult:
    """
    On-demand reputation lookup for a bare IP indicator (SS-118, SOAR
    Phase 2's ENRICH_INDICATOR action) — the same cache-before-call
    path enrich_log() already uses per-alert, reused here for a
    standalone indicator rather than duplicating the provider-lookup
    orchestration. Domain indicators aren't looked up (VirusTotal/
    AbuseIPDB clients here are IP/hash-oriented) — a non-IP indicator
    returns an empty (all-None) TIResult rather than raising.
    """
    import ipaddress

    try:
        ipaddress.ip_address(indicator)
    except ValueError:
        return TIResult()
    return await _get_ip_result(db, indicator)


async def enrich_log(db: AsyncSession, log: NormalizedLog) -> NormalizedLog:
    """
    Enrich a NormalizedLog against its primary indicator — source_ip
    takes priority over file_hash if a log somehow carries both, since
    IP reputation is the more common first SOC signal. A log with
    neither is a no-op: returned unchanged, no cache/OpenSearch writes.

    Returns a new NormalizedLog with ti_result/ti_enriched/risk_score
    set, after also writing those fields back to the OpenSearch
    document (update-by-id) and to ti_cache.
    """
    if log.source_ip:
        ti_result = await _get_ip_result(db, log.source_ip)
    elif log.file_hash:
        ti_result = await _get_hash_result(db, log.file_hash)
    else:
        return log

    risk_bonus = settings.RISK_SCORE_TI_MALICIOUS_BONUS if ti_result.is_malicious else 0
    enriched = log.model_copy(update={
        "ti_result": ti_result,
        "ti_enriched": True,
        "risk_score": log.risk_score + risk_bonus,
    })

    await update_alert_ti_fields(
        alert_id=enriched.alert_id,
        timestamp=enriched.timestamp,
        ti_result=ti_result.model_dump(mode="json"),
        ti_enriched=True,
        risk_score=enriched.risk_score,
    )

    return enriched
