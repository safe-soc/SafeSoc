"""
SafeSOC — AWS GuardDuty Adapter
Transforms a raw GuardDuty finding into NormalizedLog-shaped fields
(source is always "aws_guardduty"), mapping GuardDuty's 0.1-8.9 float
severity score to the Severity enum.

Severity boundaries (per AWS's documented GuardDuty severity bands):
    score > 8.9            -> CRITICAL  (outside GuardDuty's documented
                                          range; defensive upper catch-all)
    7.0 <= score <= 8.9     -> HIGH
    4.0 <= score <  7.0     -> MEDIUM
    0.1 <= score <  4.0     -> LOW
    missing/unparseable     -> LOW
"""

import json
from datetime import datetime, timezone
from typing import Any, Optional

from app.core.enums import LogType, Severity


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


def _map_severity(value: Any) -> Severity:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return Severity.LOW
    if score > 8.9:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def transform(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Transform a raw GuardDuty finding into a NormalizedLog-shaped dict
    (tenant_id is injected by the ingestion pipeline, not here).
    """
    resource = raw.get("Resource") or {}
    instance_details = resource.get("InstanceDetails") or {}
    network_interfaces = instance_details.get("NetworkInterfaces") or []
    access_key_details = resource.get("AccessKeyDetails") or {}

    action = (raw.get("Service") or {}).get("Action") or {}
    network_action = action.get("NetworkConnectionAction") or {}
    api_call_action = action.get("AwsApiCallAction") or {}
    # Network findings carry the remote IP on NetworkConnectionAction;
    # IAM/API findings (e.g. Recon:IAMUser/*) on AwsApiCallAction.
    remote_ip = (
        (network_action.get("RemoteIpDetails") or {}).get("IpAddressV4")
        or (api_call_action.get("RemoteIpDetails") or {}).get("IpAddressV4")
    )
    remote_port = (network_action.get("RemotePortDetails") or {}).get("Port")
    local_port = (network_action.get("LocalPortDetails") or {}).get("Port")

    host_id = (
        instance_details.get("InstanceId")
        or raw.get("AccountId")
        or "unknown-resource"
    )
    host_ip = "0.0.0.0"
    if network_interfaces:
        host_ip = network_interfaces[0].get("PrivateIpAddress") or "0.0.0.0"

    return {
        "log_type": LogType.CLOUD.value,
        "source": "aws_guardduty",
        "timestamp": _safe_timestamp(raw.get("CreatedAt")),
        "host_id": host_id,
        "host_ip": host_ip,
        "user": access_key_details.get("UserName") or "unknown",
        "action": raw.get("Type") or "UnknownFinding",
        "description": raw.get("Title") or raw.get("Description") or raw.get("Type") or "GuardDuty finding",
        "severity": _map_severity(raw.get("Severity")).value,
        "rule_id": raw.get("Id"),
        "source_ip": remote_ip,
        "source_port": _to_int(remote_port),
        "destination_port": _to_int(local_port),
        "raw_log": json.dumps(raw, default=str),
    }
