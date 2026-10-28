"""
SafeSOC — Correlation Engine
Per-endpoint, per-tenant sliding-window event storage in Redis (SRS §3.3):
sorted sets keyed by tenant_id:host_id, plus the attack-chain pattern
detectors that evaluate a host's window against a rule (SS-028; the
refinements for real-format telemetry are docs/decisions.md ADR-013).
"""

import ipaddress
import json
import ntpath
import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional, Sequence

from app.core.config import settings
from app.core.enums import CorrelationPattern, EventAction
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

    `timestamp` (unix seconds) is the sorted-set score and should be the
    EVENT's own time, not the time it happened to be processed — the
    order-sensitive detectors below read the window oldest-first, and
    concurrent Celery tasks do not finish in event order (see
    docs/decisions.md ADR-011). It defaults to now for callers with no
    better clock, and tests may backdate it directly instead of
    manipulating the real clock.

    The score is also copied into the stored member as "timestamp":
    Redis breaks ties between equal scores by comparing member strings,
    so without it two events recorded for the same instant would be
    ordered by the accident of their JSON text. The window key's Redis
    TTL is (re)set to CORRELATION_WINDOW_TTL on every write, so an idle
    host's window is cleaned up automatically once nothing has touched
    it for that long.
    """
    ts = timestamp if timestamp is not None else time.time()
    key = _window_key(tenant_id, host_id)
    member = json.dumps({**event, "timestamp": ts}, sort_keys=True)

    client = get_client()
    await client.zadd(key, {member: ts})
    await client.expire(key, settings.CORRELATION_WINDOW_TTL)


async def get_events(
    tenant_id: str,
    host_id: str,
    window_minutes: int,
    *,
    now: Optional[float] = None,
    allow_future_skew: bool = True,
) -> list[dict[str, Any]]:
    """
    Return host_id's events (tenant-scoped) from the last window_minutes,
    oldest first. Events outside the window are excluded by score
    regardless of whether Redis has physically expired the key yet, so
    "old entries don't come back" is deterministic and testable without
    waiting on real time.

    Scores are event times (see add_event), which has two consequences:

      * The ceiling is `now` + CORRELATION_CLOCK_SKEW_SECONDS, so an
        endpoint whose clock runs slightly fast still gets correlated
        instead of having its events silently skipped.
      * An event whose own timestamp is already older than
        window_minutes is NOT correlated, however recently it arrived.
        That is intended: the window means "what happened on this host
        in the last N minutes", so a late-arriving or deliberately
        backdated log (injector/demo.py seeds weeks of history) must not
        resurrect an attack chain out of events that are, in event time,
        long past.

    `allow_future_skew=False` pins the ceiling to exactly `now` — for
    callers that treat `now` as a historical point rather than "live",
    where reaching past it would pull in events the caller means to
    exclude (services/anomaly.py's non-overlapping baseline/recent
    windows).

    `now` (unix seconds) is injectable for tests; defaults to the real
    current time.
    """
    now = now if now is not None else time.time()
    floor = now - (window_minutes * 60)
    ceiling = now + settings.CORRELATION_CLOCK_SKEW_SECONDS if allow_future_skew else now
    key = _window_key(tenant_id, host_id)

    client = get_client()
    members = await client.zrangebyscore(key, floor, ceiling)
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

# Network actions that are evidence of probing, not ordinary traffic.
# Plain outbound/inbound connections and web_request are what every busy
# host does all day, so they no longer count (ADR-013). port_scan and
# suspicious_network_connection are the legacy injector vocabularies
# (injector/injector.py, injector/simulate.py); the rest are the
# canonical EventAction values adapters/mapping.py produces.
RECON_ACTIONS = frozenset({
    "port_scan",
    "suspicious_network_connection",
    EventAction.WEB_ATTACK.value,
    EventAction.IDS_ALERT.value,
    EventAction.CONNECTION_BLOCKED.value,
})


def _is_recon(event: dict[str, Any]) -> bool:
    return event.get("log_type") == "network" and event.get("action") in RECON_ACTIONS


def detect_recon_to_exploitation(
    events: Sequence[dict[str, Any]], tenant_id: str, host_id: str
) -> Optional[DetectedChain]:
    """
    The first process event with at least RECON_MIN_EVENTS recon events
    before it. Every process event is a candidate, not just the window's
    first one: a benign process early in the window must not hide an
    exploitation that follows the probing later.
    """
    prior_recon: list[dict[str, Any]] = []
    for event in events:
        if _is_recon(event):
            prior_recon.append(event)
        elif event.get("log_type") == "process" and len(prior_recon) >= RECON_MIN_EVENTS:
            confidence = _scaled_confidence(len(prior_recon), RECON_MIN_EVENTS, RECON_SATURATE_EVENTS)
            alert_ids = [e["alert_id"] for e in prior_recon] + [event["alert_id"]]
            return _build_chain(CorrelationPattern.RECON_TO_EXPLOITATION, confidence, alert_ids)
    return None


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


# 5. Data exfiltration: a high volume of outbound connections from this
# host, or of cloud object reads by one principal. NormalizedLog has no
# bytes-transferred field today, so the event *count* is used as an
# approximation for transfer volume rather than actual data measured.
#
# Cloud reads are counted per user (the CloudTrail principal), never
# pooled: a cloud window is a whole AWS account (the CloudTrail
# adapter's host_id is the account id), so pooling would let several
# applications' routine reads add up to a false exfiltration. They are
# also never mixed with network connections (ADR-013).
#
# MITRE stays this pattern's static mapping (T1041, Exfiltration Over C2
# Channel) even when the evidence is S3 GetObject calls, for which T1530
# (Data from Cloud Storage) is the more precise technique. The mapping
# is per pattern, not per evidence type (core/mitre_mapping.py, ADR-013).
EXFILTRATION_MIN_CONNECTIONS = 10
EXFILTRATION_SATURATE_CONNECTIONS = 30

# CloudTrail eventNames that read object data out of cloud storage.
CLOUD_DATA_READ_ACTIONS = frozenset({"GetObject"})


def _exfiltration_evidence(events: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    The events that qualify: this host's outbound connections if there
    are enough, otherwise the cloud reads of the single principal with
    the most reads, if that is enough. Empty if neither is.
    """
    outbound = [
        e for e in events
        if e.get("log_type") == "network" and e.get("action") == EventAction.OUTBOUND_CONNECTION.value
    ]
    if len(outbound) >= EXFILTRATION_MIN_CONNECTIONS:
        return outbound

    reads_by_user: dict[Any, list[dict[str, Any]]] = {}
    for event in events:
        if event.get("log_type") == "cloud" and event.get("action") in CLOUD_DATA_READ_ACTIONS:
            reads_by_user.setdefault(event.get("user"), []).append(event)
    busiest = max(reads_by_user.values(), key=len, default=[])  # ties: the user seen first
    return busiest if len(busiest) >= EXFILTRATION_MIN_CONNECTIONS else []


def detect_data_exfiltration(
    events: Sequence[dict[str, Any]], tenant_id: str, host_id: str
) -> Optional[DetectedChain]:
    evidence = _exfiltration_evidence(events)
    if not evidence:
        return None

    confidence = _scaled_confidence(len(evidence), EXFILTRATION_MIN_CONNECTIONS, EXFILTRATION_SATURATE_CONNECTIONS)
    return _build_chain(CorrelationPattern.DATA_EXFILTRATION, confidence, [e["alert_id"] for e in evidence])


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


# 7. Ransomware precursor: backup/recovery destruction (shadow copies,
# the backup catalog, boot recovery) and/or a burst of files created with
# one unusual extension: the two things ransomware does right before or
# while it encrypts. Either signal alone fires; both together is near
# certain.
RANSOMWARE_MIN_FILE_EVENTS = 20
_RANSOMWARE_CONFIDENCE_BOTH = 0.95
_RANSOMWARE_CONFIDENCE_SHADOW_DELETION = 0.8
_RANSOMWARE_CONFIDENCE_MASS_RENAME = 0.75

SHADOW_DELETION_PROCESSES = frozenset({"vssadmin.exe", "wmic.exe", "wbadmin.exe", "bcdedit.exe"})
_SHADOW_DELETION_COMMAND = re.compile(
    r"delete\s+shadows|shadowcopy\s+delete|delete\s+catalog|recoveryenabled\s+no", re.IGNORECASE
)

# Extensions ordinary office, system and application activity creates in
# bulk. A burst of creates with any OTHER single extension (".akira",
# ".lockbit", ...) looks like files being rewritten as encrypted copies.
COMMON_FILE_EXTENSIONS = frozenset({
    "docx", "xlsx", "pptx", "pdf", "txt", "csv", "log", "tmp", "jpg", "png", "zip", "json", "xml", "ini", "dll",
    "exe", "lnk",
})


def _is_shadow_deletion(event: dict[str, Any]) -> bool:
    if event.get("log_type") != "process":
        return False
    process_name = ntpath.basename(str(event.get("process_name") or "")).lower()
    return process_name in SHADOW_DELETION_PROCESSES and bool(
        _SHADOW_DELETION_COMMAND.search(str(event.get("command_line") or ""))
    )


def _file_extension(path: Optional[str]) -> Optional[str]:
    """Lower-case extension without the dot, for Windows or POSIX paths (ntpath splits on both); None if none."""
    _, ext = ntpath.splitext(ntpath.basename(str(path or "")))
    return ext[1:].lower() or None


def detect_ransomware_precursor(
    events: Sequence[dict[str, Any]], tenant_id: str, host_id: str
) -> Optional[DetectedChain]:
    shadow_deletion = [e for e in events if _is_shadow_deletion(e)]

    creates_by_extension: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        if event.get("action") != EventAction.FILE_CREATE.value:
            continue
        ext = _file_extension(event.get("file_path"))
        if ext and ext not in COMMON_FILE_EXTENSIONS:
            creates_by_extension.setdefault(ext, []).append(event)
    mass_rename = [
        e for group in creates_by_extension.values() if len(group) >= RANSOMWARE_MIN_FILE_EVENTS for e in group
    ]

    if shadow_deletion and mass_rename:
        confidence = _RANSOMWARE_CONFIDENCE_BOTH
    elif shadow_deletion:
        confidence = _RANSOMWARE_CONFIDENCE_SHADOW_DELETION
    elif mass_rename:
        confidence = _RANSOMWARE_CONFIDENCE_MASS_RENAME
    else:
        return None

    matched = {id(e) for e in shadow_deletion + mass_rename}
    alert_ids = [e["alert_id"] for e in events if id(e) in matched]  # window (event-time) order
    return _build_chain(CorrelationPattern.RANSOMWARE_PRECURSOR, confidence, alert_ids)


DETECTORS: tuple[Callable[[Sequence[dict[str, Any]], str, str], Optional[DetectedChain]], ...] = (
    detect_credential_brute_force,
    detect_successful_compromise,
    detect_recon_to_exploitation,
    detect_privilege_escalation,
    detect_data_exfiltration,
    detect_lateral_movement,
    detect_ransomware_precursor,
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
