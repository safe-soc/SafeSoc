"""
SafeSOC — AbuseIPDB Client
IP reputation lookups against the AbuseIPDB API v2, tracking
ABUSEIPDB_RATE_LIMIT_PER_DAY via an in-process sliding 24h counter
(acceptable for Phase 2 per the issue; Redis-backed is a stretch goal).
"""

import time
from collections import deque
from datetime import datetime
from typing import Optional

import requests

from app.core.config import settings
from app.schemas.log import AbuseIPDetails, TIResult

ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"

# AbuseIPDB's confidence score runs 0-100; 50+ is a commonly used
# "actionable" threshold in security tooling. AbuseIPDB itself doesn't
# define a fixed cutoff and there's no existing config setting for one,
# so this is a documented judgment call, not a value from the API/spec.
MALICIOUS_CONFIDENCE_THRESHOLD = 50

# The report window passed to /check — also recorded on AbuseIPDetails
# so the UI can say "N reports in the last 90 days".
MAX_AGE_IN_DAYS = 90

# Timestamps (time.monotonic()) of recent requests, for the sliding
# 24h rate-limit window.
_call_timestamps: deque[float] = deque()


class AbuseIPDBError(Exception):
    """Raised when AbuseIPDB is unreachable, returns an error, or the daily quota is exhausted."""


def _check_rate_limit() -> None:
    """
    Track calls in a sliding 24h window against ABUSEIPDB_RATE_LIMIT_PER_DAY.

    Unlike VirusTotal's per-minute limiter (app/clients/virustotal.py),
    this raises rather than blocks once the quota is hit — sleeping for
    up to a day inside a worker process isn't a workable strategy.
    """
    limit = settings.ABUSEIPDB_RATE_LIMIT_PER_DAY
    now = time.monotonic()
    while _call_timestamps and now - _call_timestamps[0] >= 86400:
        _call_timestamps.popleft()

    if len(_call_timestamps) >= limit:
        raise AbuseIPDBError(f"AbuseIPDB daily rate limit of {limit} requests reached.")

    _call_timestamps.append(now)


def _get(path: str, params: dict) -> dict:
    _check_rate_limit()
    try:
        response = requests.get(
            f"{ABUSEIPDB_BASE_URL}/{path}",
            headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params=params,
            timeout=10,
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        raise AbuseIPDBError(f"AbuseIPDB request failed: {e}") from e


def _parse_datetime(value) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(value) if isinstance(value, str) else None
    except ValueError:
        return None


def _ip_details(attributes: dict) -> AbuseIPDetails:
    return AbuseIPDetails(
        confidence=attributes.get("abuseConfidenceScore") or 0,
        total_reports=attributes.get("totalReports") or 0,
        num_distinct_users=attributes.get("numDistinctUsers") or 0,
        last_reported_at=_parse_datetime(attributes.get("lastReportedAt")),
        isp=attributes.get("isp"),
        usage_type=attributes.get("usageType"),
        domain=attributes.get("domain"),
        country_code=attributes.get("countryCode"),
        hostnames=[h for h in (attributes.get("hostnames") or []) if isinstance(h, str)],
        is_tor=bool(attributes.get("isTor")),
        is_whitelisted=attributes.get("isWhitelisted"),
        max_age_days=MAX_AGE_IN_DAYS,
    )


async def lookup_ip(ip: str) -> TIResult:
    """Look up an IP address's reputation on AbuseIPDB."""
    data = _get("check", {"ipAddress": ip, "maxAgeInDays": MAX_AGE_IN_DAYS})
    attributes = data.get("data") or {}
    confidence = attributes.get("abuseConfidenceScore", 0)

    return TIResult(
        source_ip=ip,
        abuse_confidence=confidence,
        abuse_total_reports=attributes.get("totalReports", 0),
        is_malicious=confidence >= MALICIOUS_CONFIDENCE_THRESHOLD,
        abuse=_ip_details(attributes),
    )
