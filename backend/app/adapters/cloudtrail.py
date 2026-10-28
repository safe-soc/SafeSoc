"""
SafeSOC — AWS CloudTrail Adapter
Transforms a raw CloudTrail event record into NormalizedLog-shaped
fields (source is always "aws_cloudtrail"). ConsoleLogin maps to the
canonical authentication actions (login_success / failed_login, from
responseElements.ConsoleLogin) the correlation detectors key on; every
other event keeps action = eventName and log_type "cloud".
"""

import json
from datetime import datetime, timezone
from typing import Any, Optional

from app.core.enums import EventAction, LogType, Severity

_CONSOLE_LOGIN_RESULTS = {"success": EventAction.LOGIN_SUCCESS, "failure": EventAction.FAILED_LOGIN}


def _safe_timestamp(raw_timestamp: Optional[str]) -> str:
    if raw_timestamp:
        try:
            datetime.fromisoformat(raw_timestamp.replace("Z", "+00:00"))
            return raw_timestamp
        except (ValueError, AttributeError):
            pass
    return datetime.now(timezone.utc).isoformat()


def _describe_actor(user_identity: dict[str, Any]) -> str:
    """userName, else the ARN's last path segment (an assumed-role session name, e.g. ".../dev-role/bob" -> "bob"), else type."""
    arn = user_identity.get("arn") or ""
    return (
        user_identity.get("userName")
        or (arn.rsplit("/", 1)[-1] if "/" in arn else None)
        or user_identity.get("type")
        or "unknown"
    )


def _classify(event_name: str, raw: dict[str, Any]) -> tuple[LogType, str]:
    if event_name != "ConsoleLogin":
        return LogType.CLOUD, event_name
    result = str((raw.get("responseElements") or {}).get("ConsoleLogin") or "").strip().lower()
    action = _CONSOLE_LOGIN_RESULTS.get(result)
    return LogType.AUTHENTICATION, action.value if action else event_name


def _describe_event(event_name: str, event_source: str, actor: str, resources: list[dict[str, Any]]) -> str:
    description = f"{event_name} on {event_source} by {actor}"
    resource_arns = [r["ARN"] for r in resources if r.get("ARN")]
    if resource_arns:
        description += f" (resources: {', '.join(resource_arns)})"
    return description


def transform(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Transform a raw AWS CloudTrail event record into a NormalizedLog-shaped
    dict (tenant_id is injected by the ingestion pipeline, not here).
    """
    user_identity = raw.get("userIdentity") or {}
    resources = raw.get("resources") or []
    event_name = raw.get("eventName") or "UnknownEvent"
    event_source = raw.get("eventSource") or "unknown.amazonaws.com"
    actor = _describe_actor(user_identity)

    host_id = (
        user_identity.get("accountId")
        or raw.get("recipientAccountId")
        or "unknown-account"
    )

    # A failed/denied API call (errorCode present) is materially more
    # notable than routine, successful management-plane activity.
    severity = Severity.HIGH if raw.get("errorCode") else Severity.LOW
    log_type, action = _classify(event_name, raw)

    return {
        "log_type": log_type.value,
        "source": "aws_cloudtrail",
        "timestamp": _safe_timestamp(raw.get("eventTime")),
        "host_id": host_id,
        "host_ip": "0.0.0.0",
        "user": actor,
        "action": action,
        "description": _describe_event(event_name, event_source, actor, resources),
        "severity": severity.value,
        "source_ip": raw.get("sourceIPAddress"),
        "raw_log": json.dumps(raw, default=str),
    }
