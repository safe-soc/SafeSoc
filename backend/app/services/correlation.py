"""
SafeSOC — Correlation Engine
Per-endpoint, per-tenant sliding-window event storage in Redis (SRS §3.3):
sorted sets keyed by tenant_id:host_id, plus the six attack-chain pattern
detectors that evaluate a host's window against a rule (SS-028).
"""

import ipaddress
import json
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional, Sequence

from app.core.config import settings
from app.core.enums import CorrelationPattern
from app.core.mitre_mapping import get_mitre_technique
from app.db.redis import get_client

# Namespaced to avoid colliding with other Redis usage on the same
# instance (e.g. Celery's own broker/result keys).
WINDOW_KEY_PREFIX = "correlation:window"


def _window_key(tenant_id: str, host_id: str) -> str:
    return f"{WINDOW_KEY_PREFIX}:{tenant_id}:{host_id}"


async def add_event(
    tenant_id: str,
    host_id: str,
    event: dict[str, Any],
    timestamp: Optional[float] = None,
) -> None:
    """
    Record an event in host_id's sliding window for tenant_id.

    `timestamp` (unix seconds) is the sorted-set score; defaults to now,
    but callers (tests) may backdate it directly instead of manipulating
    the real clock. The window key's Redis TTL is (re)set to
    CORRELATION_WINDOW_TTL on every write, so an idle host's window is
    cleaned up automatically once nothing has touched it for that long.
    """
    ts = timestamp if timestamp is not None else time.time()
    key = _window_key(tenant_id, host_id)
    member = json.dumps(event, sort_keys=True)

    client = get_client()
    await client.zadd(key, {member: ts})
    await client.expire(key, settings.CORRELATION_WINDOW_TTL)


async def get_events(
    tenant_id: str,
    host_id: str,
    window_minutes: int,
    *,
    now: Optional[float] = None,
) -> list[dict[str, Any]]:
    """
    Return host_id's events (tenant-scoped) from the last window_minutes,
    oldest first. Events outside the window are excluded by score
    regardless of whether Redis has physically expired the key yet, so
    "old entries don't come back" is deterministic and testable without
    waiting on real time.

    `now` (unix seconds) is injectable for tests; defaults to the real
    current time.
    """
    now = now if now is not None else time.time()
    floor = now - (window_minutes * 60)
    key = _window_key(tenant_id, host_id)

    client = get_client()
    members = await client.zrangebyscore(key, floor, now)
    return [json.loads(member) for member in members]


# ── Pattern detectors (SS-028) ─────────────────────────────────
#
# Each detector evaluates a host's current window (oldest-first, as
# returned by get_events()) against one attack-chain rule from SRS §3.3.
# A detector returns None if its rule doesn't match at all; if it does,
# it computes a confidence score and returns a DetectedChain carrying
# the MITRE technique(s)/tactic for that pattern (SS-029).


@dataclass(frozen=True)
class DetectedChain:
    pattern: CorrelationPattern
    confidence: float
    alert_ids: tuple[str, ...]
    mitre_technique_ids: tuple[str, ...]
    mitre_tactic: str


def _build_chain(pattern: CorrelationPattern, confidence: float, alert_ids: Sequence[str]) -> DetectedChain:
    mitre = get_mitre_technique(pattern)
    return DetectedChain(
        pattern=pattern,
        confidence=confidence,
        alert_ids=tuple(alert_ids),
        mitre_technique_ids=mitre.technique_ids,
        mitre_tactic=mitre.tactic,
    )


def _scaled_confidence(count: int, minimum: int, saturate_at: int) -> float:
    """
    Linear confidence scaling: `minimum` occurrences of the triggering
    evidence -> CORRELATION_CONFIDENCE_THRESHOLD exactly (the least
    evidence that still counts as a detection), `saturate_at` or more
    -> 1.0.
    """
    threshold = settings.CORRELATION_CONFIDENCE_THRESHOLD
    if saturate_at <= minimum:
        return 1.0
    fraction = (count - minimum) / (saturate_at - minimum)
    return min(1.0, threshold + fraction * (1.0 - threshold))


def _is_private_destination(event: dict[str, Any]) -> bool:
    destination_ip = event.get("destination_ip")
    if not destination_ip:
        return False
    try:
        return ipaddress.ip_address(destination_ip).is_private
    except ValueError:
        return False


# 1. Credential brute force: enough failed logins against one host.
BRUTE_FORCE_MIN_ATTEMPTS = 5
BRUTE_FORCE_SATURATE_ATTEMPTS = 15


def detect_credential_brute_force(
    events: Sequence[dict[str, Any]], tenant_id: str, host_id: str
) -> Optional[DetectedChain]:
    failed_logins = [e for e in events if e.get("action") == "failed_login"]
    if len(failed_logins) < BRUTE_FORCE_MIN_ATTEMPTS:
        return None

    confidence = _scaled_confidence(len(failed_logins), BRUTE_FORCE_MIN_ATTEMPTS, BRUTE_FORCE_SATURATE_ATTEMPTS)
    return _build_chain(
        CorrelationPattern.CREDENTIAL_BRUTE_FORCE, confidence, [e["alert_id"] for e in failed_logins]
    )


# 2. Successful compromise: brute force that then actually succeeds.
def detect_successful_compromise(
    events: Sequence[dict[str, Any]], tenant_id: str, host_id: str
) -> Optional[DetectedChain]:
    success_index = next((i for i, e in enumerate(events) if e.get("action") == "login_success"), None)
    if success_index is None:
        return None

    prior_failed_logins = [e for e in events[:success_index] if e.get("action") == "failed_login"]
    if len(prior_failed_logins) < BRUTE_FORCE_MIN_ATTEMPTS:
        return None

    confidence = _scaled_confidence(
        len(prior_failed_logins), BRUTE_FORCE_MIN_ATTEMPTS, BRUTE_FORCE_SATURATE_ATTEMPTS
    )
    alert_ids = [e["alert_id"] for e in prior_failed_logins] + [events[success_index]["alert_id"]]
    return _build_chain(CorrelationPattern.SUCCESSFUL_COMPROMISE, confidence, alert_ids)


# 3. Recon-to-exploitation: scanning/probing activity, then process execution.
RECON_MIN_EVENTS = 3
RECON_SATURATE_EVENTS = 10


def detect_recon_to_exploitation(
    events: Sequence[dict[str, Any]], tenant_id: str, host_id: str
) -> Optional[DetectedChain]:
    exploit_index = next((i for i, e in enumerate(events) if e.get("log_type") == "process"), None)
    if exploit_index is None:
        return None

    prior_recon = [e for e in events[:exploit_index] if e.get("log_type") == "network"]
    if len(prior_recon) < RECON_MIN_EVENTS:
        return None

    confidence = _scaled_confidence(len(prior_recon), RECON_MIN_EVENTS, RECON_SATURATE_EVENTS)
    alert_ids = [e["alert_id"] for e in prior_recon] + [events[exploit_index]["alert_id"]]
    return _build_chain(CorrelationPattern.RECON_TO_EXPLOITATION, confidence, alert_ids)


# 4. Privilege escalation: an authenticated session followed by a
# high/critical-severity privilege-context change.
_PRIVILEGE_ESCALATION_CONFIDENCE = {"critical": 0.95, "high": 0.75}


def detect_privilege_escalation(
    events: Sequence[dict[str, Any]], tenant_id: str, host_id: str
) -> Optional[DetectedChain]:
    login_alert_id: Optional[str] = None
    for event in events:
        if event.get("action") == "login_success":
            login_alert_id = event.get("alert_id")
            continue
        if login_alert_id and event.get("log_type") == "privilege":
            confidence = _PRIVILEGE_ESCALATION_CONFIDENCE.get(event.get("severity"))
            if confidence is None:
                continue
            return _build_chain(
                CorrelationPattern.PRIVILEGE_ESCALATION, confidence, [login_alert_id, event["alert_id"]]
            )
    return None


# 5. Data exfiltration: a high volume of outbound connections. NormalizedLog
# has no bytes-transferred field today, so connection *count* is used as an
# approximation for transfer volume rather than actual data measured.
EXFILTRATION_MIN_CONNECTIONS = 10
EXFILTRATION_SATURATE_CONNECTIONS = 30


def detect_data_exfiltration(
    events: Sequence[dict[str, Any]], tenant_id: str, host_id: str
) -> Optional[DetectedChain]:
    outbound = [e for e in events if e.get("log_type") == "network" and e.get("action") == "outbound_connection"]
    if len(outbound) < EXFILTRATION_MIN_CONNECTIONS:
        return None

    confidence = _scaled_confidence(len(outbound), EXFILTRATION_MIN_CONNECTIONS, EXFILTRATION_SATURATE_CONNECTIONS)
    return _build_chain(CorrelationPattern.DATA_EXFILTRATION, confidence, [e["alert_id"] for e in outbound])


# 6. Lateral movement: after authenticating on this host, an outbound
# connection to another *internal* host — i.e. this host used as a pivot.
# Sliding windows are per-host (SS-027), so this approximates lateral
# movement as "staging from here" rather than tracking a chain across
# multiple hosts' windows, which is out of this issue's scope.
LATERAL_MOVEMENT_MIN_CONNECTIONS = 1
LATERAL_MOVEMENT_SATURATE_CONNECTIONS = 5


def detect_lateral_movement(
    events: Sequence[dict[str, Any]], tenant_id: str, host_id: str
) -> Optional[DetectedChain]:
    login_alert_id: Optional[str] = None
    pivot_events: list[dict[str, Any]] = []
    for event in events:
        if event.get("action") == "login_success":
            login_alert_id = event.get("alert_id")
            continue
        if login_alert_id and event.get("log_type") == "network" and _is_private_destination(event):
            pivot_events.append(event)

    if login_alert_id is None or len(pivot_events) < LATERAL_MOVEMENT_MIN_CONNECTIONS:
        return None

    confidence = _scaled_confidence(
        len(pivot_events), LATERAL_MOVEMENT_MIN_CONNECTIONS, LATERAL_MOVEMENT_SATURATE_CONNECTIONS
    )
    alert_ids = [login_alert_id] + [e["alert_id"] for e in pivot_events]
    return _build_chain(CorrelationPattern.LATERAL_MOVEMENT, confidence, alert_ids)


DETECTORS: tuple[Callable[[Sequence[dict[str, Any]], str, str], Optional[DetectedChain]], ...] = (
    detect_credential_brute_force,
    detect_successful_compromise,
    detect_recon_to_exploitation,
    detect_privilege_escalation,
    detect_data_exfiltration,
    detect_lateral_movement,
)


async def evaluate_host(
    tenant_id: str,
    host_id: str,
    window_minutes: int = 60,
    *,
    now: Optional[float] = None,
) -> list[DetectedChain]:
    """Fetch host_id's current sliding window and run every pattern detector against it."""
    events = await get_events(tenant_id, host_id, window_minutes, now=now)
    return [chain for chain in (detector(events, tenant_id, host_id) for detector in DETECTORS) if chain is not None]
