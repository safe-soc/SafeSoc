"""
SafeSOC — CloudLens Adapter
Transforms a CloudLens Finding (see FindingSerializer in
cloud/AWS-IAM-backend/core/serializers.py: id, category, title,
description, severity, affected_resource, remediation) into
NormalizedLog-shaped fields (log_type is always "cloud", source is
always "cloudlens").

A Finding is a static IAM misconfiguration result, not a timestamped
event — CloudLens's own model has no per-finding timestamp field
(only Scan.scan_time does, which isn't part of the serialized Finding),
so timestamp is always "now": the moment SafeSOC ingests it.
"""

import json
from datetime import datetime, timezone
from typing import Any

from app.core.enums import LogType, Severity

# CloudLens's Finding.SEVERITY_CHOICES are uppercase (CRITICAL/HIGH/
# MEDIUM/LOW); SafeSOC's Severity enum values are lowercase. Confirmed
# explicitly per the AC rather than assumed to just lowercase-match.
_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def _map_severity(value: Any) -> Severity:
    return _SEVERITY_MAP.get(str(value).upper(), Severity.LOW)


def _describe(title: str, description: str, remediation: str) -> str:
    parts = [p for p in (title, description) if p]
    text = ": ".join(parts) if parts else "CloudLens finding"
    if remediation:
        text += f" | Remediation: {remediation}"
    return text


def transform(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Transform a raw CloudLens Finding dict into a NormalizedLog-shaped
    dict (tenant_id is injected by the ingestion pipeline, not here).
    """
    affected_resource = raw.get("affected_resource") or "unknown-resource"

    return {
        "log_type": LogType.CLOUD.value,
        "source": "cloudlens",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host_id": affected_resource,
        "host_ip": "0.0.0.0",
        "action": raw.get("category") or "UnknownFinding",
        "description": _describe(raw.get("title", ""), raw.get("description", ""), raw.get("remediation", "")),
        "severity": _map_severity(raw.get("severity")).value,
        "rule_id": str(raw["id"]) if raw.get("id") is not None else None,
        "raw_log": json.dumps(raw, default=str),
    }
