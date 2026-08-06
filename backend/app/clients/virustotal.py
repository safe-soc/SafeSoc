"""
SafeSOC — VirusTotal Client
IP and file-hash reputation lookups against the VirusTotal API v3,
rate-limited client-side per settings.VT_RATE_LIMIT_PER_MINUTE.
"""

import time
from collections import deque

import requests

from app.core.config import settings
from app.schemas.log import TIResult

VT_BASE_URL = "https://www.virustotal.com/api/v3"

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


async def lookup_ip(ip: str) -> TIResult:
    """Look up an IP address's reputation on VirusTotal."""
    data = _get(f"ip_addresses/{ip}")
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return _stats_to_result(stats, source_ip=ip)


async def lookup_hash(file_hash: str) -> TIResult:
    """Look up a file hash's reputation on VirusTotal."""
    data = _get(f"files/{file_hash}")
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return _stats_to_result(stats, file_hash=file_hash)
