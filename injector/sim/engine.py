"""
SafeSOC — Simulator Ingest Engine
Sends source-native events to POST /api/v1/ingest: logs in with the
same helper injector.py uses, groups events by source, and posts each
source's events as {"source": <source>, "logs": [...]} in batches no
larger than the backend accepts. Reports accepted/rejected per source.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

import requests

from injector.injector import login

FALLBACK_BATCH_SIZE = 100
_BACKEND_CONFIG = Path(__file__).resolve().parents[2] / "backend" / "app" / "core" / "config.py"


def backend_batch_size(config_path: Path = _BACKEND_CONFIG) -> int:
    """INGEST_BATCH_SIZE's default from backend/app/core/config.py, or 100 when that file isn't available."""
    try:
        match = re.search(r"INGEST_BATCH_SIZE\s*:\s*int\s*=\s*(\d+)", config_path.read_text(encoding="utf-8"))
    except OSError:
        return FALLBACK_BATCH_SIZE
    return int(match.group(1)) if match else FALLBACK_BATCH_SIZE


def authenticate(api_base: str, tenant_id: str, email: str, password: str) -> str:
    """A JWT access token, via injector.py's own login() (same endpoint, same demo-tenant defaults)."""
    return login(api_base, tenant_id, email, password)


@dataclass
class SourceResult:
    accepted: int = 0
    rejected: int = 0
    alert_ids: list[str] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)


def group_by_source(events: Iterable[tuple[str, dict]]) -> dict[str, list[dict]]:
    """{source: [payload, ...]} in first-seen source order, keeping each source's event order."""
    grouped: dict[str, list[dict]] = {}
    for source, payload in events:
        grouped.setdefault(source, []).append(payload)
    return grouped


def send_events(
    events: Iterable[tuple[str, dict]],
    *,
    api_base: str,
    token: str,
    batch_size: Optional[int] = None,
    session: Optional[requests.Session] = None,
    timeout: float = 30,
) -> dict[str, SourceResult]:
    """POST every event; raises requests.HTTPError on a non-2xx response (e.g. an unknown source)."""
    size = batch_size or backend_batch_size()
    http = session or requests.Session()
    headers = {"Authorization": f"Bearer {token}"}
    results: dict[str, SourceResult] = {}
    for source, payloads in group_by_source(events).items():
        result = results.setdefault(source, SourceResult())
        for start in range(0, len(payloads), size):
            batch = payloads[start:start + size]
            response = http.post(
                f"{api_base}/api/v1/ingest", json={"source": source, "logs": batch}, headers=headers, timeout=timeout,
            )
            response.raise_for_status()
            body = response.json()
            result.accepted += body.get("accepted", 0)
            result.rejected += body.get("rejected", 0)
            result.alert_ids.extend(body.get("alert_ids") or [])
            for error in body.get("errors") or []:
                # Report the index within this source's whole event list, not within the batch.
                result.errors.append({**error, "index": start + error.get("index", 0)})
    return results
