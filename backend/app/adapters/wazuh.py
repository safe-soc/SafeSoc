"""
SafeSOC — Wazuh Adapter
Transforms a raw Wazuh alert JSON payload into NormalizedLog-shaped fields.
What the event means (canonical log_type/action, users, network,
process and file fields) is resolved by adapters/mapping.py; this
module supplies the envelope (host, time, rule, severity) and the
fallback for events no mapping recognises.
Missing or unmappable fields degrade gracefully (sensible defaults for
required fields, None for optional ones) rather than raising, so a log
is always accepted rather than rejected for an adapter-level reason.
"""

import json
from datetime import datetime, timezone
from typing import Any, Optional

from app.adapters.mapping import map_wazuh_event
from app.core.enums import LogType, Severity

# Fallback for events adapters/mapping.py doesn't recognise:
# Wazuh decoder/rule-group keywords -> LogType, checked in order (first match wins).
_LOG_TYPE_KEYWORDS: list[tuple[str, LogType]] = [
    ("authentication", LogType.AUTHENTICATION),
    ("sshd", LogType.AUTHENTICATION),
    ("pam", LogType.AUTHENTICATION),
    ("logon", LogType.AUTHENTICATION),
    ("firewall", LogType.NETWORK),
    ("network", LogType.NETWORK),
    ("web", LogType.NETWORK),
    ("process", LogType.PROCESS),
    ("syscheck", LogType.FILE),
    ("rootcheck", LogType.PRIVILEGE),
    ("privilege_escalation", LogType.PRIVILEGE),
    ("sudo", LogType.PRIVILEGE),
]


def _infer_log_type(decoder_name: str, groups: list[str]) -> LogType:
    haystack = " ".join([decoder_name, *groups]).lower()
    for keyword, log_type in _LOG_TYPE_KEYWORDS:
        if keyword in haystack:
            return log_type
    return LogType.SYSTEM


def _map_severity(level: Any) -> Severity:
    """Wazuh rule levels run 0-15; bands per Wazuh's own documented severity guidance."""
    try:
        level_int = int(level)
    except (TypeError, ValueError):
        return Severity.LOW
    if level_int >= 12:
        return Severity.CRITICAL
    if level_int >= 8:
        return Severity.HIGH
    if level_int >= 4:
        return Severity.MEDIUM
    return Severity.LOW


def _safe_timestamp(raw_timestamp: Optional[str]) -> str:
    if raw_timestamp:
        try:
            datetime.fromisoformat(raw_timestamp.replace("Z", "+00:00"))
            return raw_timestamp
        except (ValueError, AttributeError):
            pass
    return datetime.now(timezone.utc).isoformat()


def transform(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Transform a raw Wazuh alert JSON payload into a NormalizedLog-shaped
    dict (tenant_id/source are injected by the ingestion pipeline, not
    here). Every NormalizedLog-required field always gets a value, even
    from a sparse/malformed payload, so validation never rejects a log
    purely for something this adapter couldn't map.
    """
    rule = raw.get("rule") or {}
    agent = raw.get("agent") or {}
    mitre = rule.get("mitre") or {}
    decoder_name = (raw.get("decoder") or {}).get("name") or ""
    groups = rule.get("groups") or []

    mitre_ids = mitre.get("id") or []
    mitre_tactics = mitre.get("tactic") or []

    return {
        "log_type": _infer_log_type(decoder_name, groups).value,
        "timestamp": _safe_timestamp(raw.get("timestamp")),
        "host_id": agent.get("name") or agent.get("id") or "unknown-host",
        "host_ip": agent.get("ip") or "0.0.0.0",
        "user": "unknown",
        "action": decoder_name or "unknown",
        "description": rule.get("description") or "Wazuh alert",
        "severity": _map_severity(rule.get("level")).value,
        "rule_id": str(rule["id"]) if rule.get("id") is not None else None,
        "mitre_technique": ", ".join(mitre_ids) or None,
        "mitre_tactic": ", ".join(mitre_tactics) or None,
        "raw_log": json.dumps(raw, default=str),
        # Semantic fields override the fallbacks above when resolved.
        **map_wazuh_event(raw),
    }
