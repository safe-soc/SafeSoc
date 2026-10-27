"""
SafeSOC — VirusTotal Client
IP and file-hash reputation lookups against the VirusTotal API v3,
rate-limited client-side per settings.VT_RATE_LIMIT_PER_MINUTE.
"""

import time
from collections import deque
from datetime import datetime, timezone
from typing import Optional

import requests

from app.core.config import settings
from app.schemas.log import TIResult, VTFlaggedEngine, VTIPDetails

VT_BASE_URL = "https://www.virustotal.com/api/v3"

# Cap on engines listed in VTIPDetails.flagged_by — enough to show who
# flagged an IP without storing VT's full ~90-engine verdict table.
FLAGGED_BY_LIMIT = 20

# Timestamps (time.monotonic()) of recent requests, for the sliding
# 60s rate-limit window. Module-level so the limit is enforced across
# every call in this process, not reset per-lookup.
_call_timestamps: deque[float] = deque()


class VirusTotalError(Exception):
    """Raised when the VirusTotal API is unreachable or returns an error."""


def _enforce_rate_limit() -> None:
    """Block until a request is allowed under VT_RATE_LIMIT_PER_MINUTE (sliding 60s window)."""
    limit = settings.VT_RATE_LIMIT_PER_MINUTE
    now = time.monotonic()
    while _call_timestamps and now - _call_timestamps[0] >= 60:
        _call_timestamps.popleft()

    if len(_call_timestamps) >= limit:
        time.sleep(max(0.0, 60 - (now - _call_timestamps[0])))
        now = time.monotonic()
        while _call_timestamps and now - _call_timestamps[0] >= 60:
            _call_timestamps.popleft()

    _call_timestamps.append(time.monotonic())


def _get(path: str) -> dict:
    _enforce_rate_limit()
    try:
        response = requests.get(
            f"{VT_BASE_URL}/{path}",
            headers={"x-apikey": settings.VT_API_KEY},
            timeout=10,
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        raise VirusTotalError(f"VirusTotal request failed: {e}") from e


def _stats_to_result(stats: dict, **identity) -> TIResult:
    malicious = stats.get("malicious", 0)
    total = sum(stats.get(k, 0) for k in ("malicious", "suspicious", "undetected", "harmless", "timeout"))
    return TIResult(vt_malicious=malicious, vt_total=total, is_malicious=malicious > 0, **identity)


def _epoch_to_datetime(value) -> Optional[datetime]:
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc) if value is not None else None
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _flagged_by(results: dict) -> list[VTFlaggedEngine]:
    """Only engines that called the IP malicious or suspicious — malicious first, then by engine name."""
    flagged = []
    for engine, entry in (results or {}).items():
        if not isinstance(entry, dict) or entry.get("category") not in ("malicious", "suspicious"):
            continue
        flagged.append(VTFlaggedEngine(engine=entry.get("engine_name") or engine, category=entry["category"], result=entry.get("result")))
    flagged.sort(key=lambda f: (f.category != "malicious", f.engine.lower()))
    return flagged[:FLAGGED_BY_LIMIT]


def _ip_details(attributes: dict, stats: dict, total: int) -> VTIPDetails:
    return VTIPDetails(
        malicious=stats.get("malicious") or 0,
        suspicious=stats.get("suspicious") or 0,
        harmless=stats.get("harmless") or 0,
        undetected=stats.get("undetected") or 0,
        total=total,
        reputation=attributes.get("reputation"),
        asn=attributes.get("asn"),
        as_owner=attributes.get("as_owner"),
        network=attributes.get("network"),
        country=attributes.get("country"),
        last_analysis_date=_epoch_to_datetime(attributes.get("last_analysis_date")),
        tags=[t for t in (attributes.get("tags") or []) if isinstance(t, str)],
        flagged_by=_flagged_by(attributes.get("last_analysis_results")),
    )


async def lookup_ip(ip: str) -> TIResult:
    """Look up an IP address's reputation on VirusTotal."""
    data = _get(f"ip_addresses/{ip}")
    attributes = (data.get("data") or {}).get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    result = _stats_to_result(stats, source_ip=ip)
    result.vt = _ip_details(attributes, stats, result.vt_total)
    return result


async def lookup_hash(file_hash: str) -> TIResult:
    """Look up a file hash's reputation on VirusTotal."""
    data = _get(f"files/{file_hash}")
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return _stats_to_result(stats, file_hash=file_hash)
