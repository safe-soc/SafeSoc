"""
SafeSOC — Wazuh Adapter
Transforms a raw Wazuh alert JSON payload into NormalizedLog-shaped fields.
Missing or unmappable fields degrade gracefully (sensible defaults for
required fields, None for optional ones) rather than raising, so a log
is always accepted rather than rejected for an adapter-level reason.
"""

import json
from datetime import datetime, timezone
from typing import Any, Optional

from app.core.enums import LogType, Severity

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


def _to_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


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
    data = raw.get("data") or {}
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
        "user": data.get("dstuser") or data.get("srcuser") or "unknown",
        "action": decoder_name or "unknown",
        "description": rule.get("description") or "Wazuh alert",
        "severity": _map_severity(rule.get("level")).value,
        "rule_id": str(rule["id"]) if rule.get("id") is not None else None,
        "mitre_technique": ", ".join(mitre_ids) or None,
        "mitre_tactic": ", ".join(mitre_tactics) or None,
        "source_ip": data.get("srcip"),
        "source_port": _to_int(data.get("srcport")),
        "destination_ip": data.get("dstip"),
        "destination_port": _to_int(data.get("dstport")),
        "raw_log": json.dumps(raw, default=str),
    }
