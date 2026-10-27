"""
SafeSOC — MCP Tool Definitions
Typed, per-intent tool definitions the investigation assistant
orchestrates calls to (SS-045), per the report's stated architecture
(§3.3): the LLM selects and calls one of these pre-built queries based
on the classified intent (SS-044) rather than generating raw database
queries itself.

Each tool wraps an EXISTING service function
(db.opensearch.search_alerts, services.risk_scoring, services.incidents)
— none of them duplicate query logic; they only shape parameters and
results around a specific intent.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Awaitable, Callable, Optional

from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Intent, IncidentStatus, RiskLevel
from app.core.mitre_mapping import incident_technique_ids
from app.db.opensearch import search_alerts
from app.models.endpoint import Endpoint
from app.models.incident import Incident
from app.services.incident_evidence import get_incident_evidence
from app.services.incident_summary import IncidentSummary, category_label, summarize_incidents
from app.services.incident_timeline import get_incident_timeline
from app.services.incidents import get_incident, list_incidents
from app.services.risk_scoring import get_endpoint, list_endpoints


def _endpoint_to_dict(endpoint: Endpoint) -> dict:
    return {
        "host_id": endpoint.host_id,
        "risk_score": endpoint.risk_score,
        "risk_level": endpoint.risk_level.value,
        "updated_at": endpoint.updated_at.isoformat(),
    }


def _incident_to_dict(incident: Incident, summary: Optional[IncidentSummary] = None) -> dict:
    """
    An incident as the assistant should see it: what was detected
    (category + readable label), where (hosts), how bad (severity,
    confidence), which MITRE techniques, and its lifecycle status. An
    incident is a detected attack chain; open/investigating ones are
    the active chains. hosts/severity/techniques come from
    services/incident_summary.py (one batched alert lookup per call).
    """
    summary = summary or IncidentSummary()
    return {
        "id": str(incident.id),
        "category": incident.category.value if incident.category else None,
        "category_label": category_label(incident.category),
        "status": incident.status.value,
        "hosts": summary.hosts,
        "severity": summary.severity.value if summary.severity else None,
        "confidence": round(incident.confidence, 2) if incident.confidence is not None else None,
        "mitre_techniques": summary.mitre_techniques,
        "alert_count": len(incident.alert_ids),
        "created_at": incident.created_at.isoformat(),
        "updated_at": incident.updated_at.isoformat(),
    }


_ACTIVE_STATUSES = (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING)
# How many incidents a status-wide listing considers; more than any
# tenant's open set in practice, and the response reports the true total.
_INCIDENT_LIST_LIMIT = 100


async def _incidents_with_summaries(
    db: AsyncSession, tenant_id: uuid.UUID, status: Optional[IncidentStatus] = None
) -> tuple[list[dict], int]:
    incidents, total = await list_incidents(db, tenant_id, status=status, size=_INCIDENT_LIST_LIMIT)
    summaries = await summarize_incidents(incidents)
    return [_incident_to_dict(incident, summaries.get(incident.id)) for incident in incidents], total


# ── Search scope, stated in every alert-backed result ───────────────
# The model must say what was searched before answering, and never
# claim something doesn't exist outside that scope. So each tool writes
# down its own scope in plain words.

def _format_bound(iso: str) -> str:
    try:
        moment = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return iso
    return moment.astimezone(timezone.utc).strftime("%d %b %Y %H:%M UTC")


def _window_text(params: "_Window") -> str:
    if params.start and params.end:
        return f"between {_format_bound(params.start)} and {_format_bound(params.end)}"
    if params.start:
        return f"since {_format_bound(params.start)}"
    hours = params.timerange_hours
    if hours == 1:
        return "in the last hour"
    if hours >= 48 and hours % 24 == 0:
        return f"in the last {hours // 24} days"
    return f"in the last {hours} hours"


def _scope(what: str, params: "_Window", **qualifiers: Optional[str]) -> str:
    parts = [f"Searched {what}"]
    for label, value in qualifiers.items():
        if value:
            parts.append(f"{label.replace('_', ' ')} {value}")
    parts.append(_window_text(params))
    return " ".join(parts) + "."


def _window_kwargs(params: "_Window") -> dict:
    return {"timerange_hours": params.timerange_hours, "start": params.start, "end": params.end}


# Human labels for the per-field counts handed to the model and the
# evidence panel. "user" is the account targeted or used, "source_ip"
# where the activity came from — never conflate them.
_COUNT_LABELS = {
    "source_ip": "Source IPs (where the activity came from)",
    "destination_ip": "Destination IPs",
    "user": "Accounts targeted or used",
    "host_id": "Hosts",
    "action": "Activity types",
    "severity": "Severity",
    "log_type": "Log types",
}


def _labeled_counts(counts: dict[str, dict[str, int]]) -> dict[str, dict[str, int]]:
    labeled = {}
    for field, values in counts.items():
        if field == "user":
            # "unknown" is the ingestion placeholder, not an account.
            values = {name: count for name, count in values.items() if name.lower() != "unknown"}
        if values:
            labeled[_COUNT_LABELS.get(field, field)] = values
    return labeled


def _alert_list_output(result: dict, scope: str = "") -> "AlertListOutput":
    """
    Shared by every tool backed by search_alerts (SS-086). `result["total"]`
    is a genuine full-match count (search_alerts sets track_total_hits),
    while `result["alerts"]` is capped by the `size` each tool queries
    with — so truncation is always knowable by comparing the two,
    without any extra query.
    """
    return AlertListOutput(
        scope=scope,
        total=result["total"],
        counts=_labeled_counts(result.get("counts", {})),
        alerts=result["alerts"],
        truncated=result["total"] > len(result["alerts"]),
    )


# ── Input/output schemas (one pair per intent) ────────────────────

class _Window(BaseModel):
    """A trailing timerange_hours, or a bounded [start, end) window (ISO) when start is given."""
    timerange_hours: int = Field(24, ge=1, le=24 * 90)
    start: Optional[str] = None
    end: Optional[str] = None


class AuthFailuresInput(_Window):
    host_id: Optional[str] = None
    user: Optional[str] = None


class IPActivityInput(_Window):
    ip: str


class EndpointSnapshotInput(_Window):
    host_id: str


class TopAlertsInput(_Window):
    severity: Optional[str] = None
    host_id: Optional[str] = None
    log_type: Optional[str] = None
    action: Optional[str] = None
    user: Optional[str] = None


class UserActivityInput(_Window):
    user: str


class CloudEventsInput(_Window):
    pass


class RiskyEndpointsInput(BaseModel):
    limit: int = Field(10, ge=1, le=50)


class AttackChainStatusInput(BaseModel):
    status: Optional[IncidentStatus] = None


class OverviewInput(_Window):
    pass


class AlertListOutput(BaseModel):
    # Plain-words description of what was searched (filters + window).
    scope: str = ""
    total: int
    # Per-field counts over ALL matches, keyed by a readable label.
    counts: dict[str, dict[str, int]] = {}
    alerts: list[dict]
    # True when `total` exceeds len(alerts) — i.e. this tool's own size
    # cap left out real matches (SS-086). Defaults False so any other
    # construction site (e.g. existing tests) keeps prior behavior.
    truncated: bool = False


class EndpointSnapshotOutput(BaseModel):
    scope: str = ""
    host_id: str
    risk_score: Optional[int] = None
    risk_level: Optional[RiskLevel] = None
    last_scored_at: Optional[datetime] = None
    recent_alert_count: int
    counts: dict[str, dict[str, int]] = {}
    # The "did they get in?" signal: a login_success on this host after
    # failed_login attempts on it — the same host-level sequence the
    # correlation engine's successful_compromise pattern detects.
    successful_login_after_failures: bool = False
    # Stronger: the success came from a source IP that had itself failed.
    same_source_success_after_failures: bool = False
    logins_after_failures: list[dict] = []
    open_incidents: list[dict] = []
    recent_alerts: list[dict]
    truncated: bool = False


class RiskyEndpointsOutput(BaseModel):
    endpoints: list[dict]
    truncated: bool = False


class AttackChainStatusOutput(BaseModel):
    total: int
    # Incidents are detected attack chains; open + investigating = active.
    active_count: int = 0
    counts: dict[str, dict[str, int]] = {}
    incidents: list[dict]
    truncated: bool = False


class OverviewOutput(BaseModel):
    scope: str = ""
    # Every alert in the window (critical_high_total is the subset below).
    total_alerts: int
    counts: dict[str, dict[str, int]] = {}
    critical_high_total: int = 0
    critical_high_alerts: list[dict] = []
    active_incident_count: int = 0
    active_incidents: list[dict] = []
    truncated: bool = False


# ── Tool handlers ──────────────────────────────────────────────────
# Every handler takes the same (db, tenant_id, params) shape, even
# though OpenSearch-only tools don't need `db` — a uniform calling
# convention keeps the orchestration layer (SS-046/SS-047) simple,
# with no per-tool special-casing needed to invoke one. Every search is
# tenant-scoped by search_alerts' mandatory tenant_id filter.

async def _auth_failures(db: AsyncSession, tenant_id: uuid.UUID, params: AuthFailuresInput) -> AlertListOutput:
    result = await search_alerts(
        tenant_id=str(tenant_id),
        action="failed_login",
        host_id=params.host_id,
        user=params.user,
        size=100,
        aggregate_by=["source_ip", "user", "host_id"],
        **_window_kwargs(params),
    )
    scope = _scope("failed logins", params, on=params.host_id, for_user=params.user)
    return _alert_list_output(result, scope)


async def _ip_activity(db: AsyncSession, tenant_id: uuid.UUID, params: IPActivityInput) -> AlertListOutput:
    result = await search_alerts(
        tenant_id=str(tenant_id), ip=params.ip, size=100,
        aggregate_by=["host_id", "user", "action"], **_window_kwargs(params),
    )
    scope = _scope(f"all alerts with {params.ip} as source or destination", params)
    return _alert_list_output(result, scope)


def _logins_after_failures(failures: list[dict], successes: list[dict]) -> list[dict]:
    """
    Every login_success on the host that came after at least one
    failed_login on it, with how many failures preceded it — on the host
    and from the success's own source IP (the stronger signal; real
    brute force often rotates IPs, so host-level is the headline).
    """
    failure_times = sorted(alert["timestamp"] for alert in failures if alert.get("timestamp"))
    if not failure_times:
        return []

    found = []
    for alert in sorted(successes, key=lambda a: a.get("timestamp", "")):
        success_at = alert.get("timestamp", "")
        if success_at <= failure_times[0]:
            continue
        ip = alert.get("source_ip")
        before = [f for f in failures if f.get("timestamp", "") < success_at]
        same_source = [f for f in before if ip and f.get("source_ip") == ip]
        found.append({
            "source_ip": ip,
            "user": alert.get("user"),
            "success_at": success_at,
            "failed_attempts_before": len(before),
            "failed_attempts_from_same_source": len(same_source),
        })
    return found


async def _endpoint_snapshot(
    db: AsyncSession, tenant_id: uuid.UUID, params: EndpointSnapshotInput
) -> EndpointSnapshotOutput:
    tenant = str(tenant_id)
    endpoint = await get_endpoint(db, tenant_id, params.host_id)
    window = _window_kwargs(params)
    # Every alert type for this host, not just failures.
    alerts_result = await search_alerts(
        tenant_id=tenant, host_id=params.host_id, size=20, aggregate_by=["action", "severity"], **window
    )
    failures = await search_alerts(tenant_id=tenant, host_id=params.host_id, action="failed_login", size=200, **window)
    successes = await search_alerts(tenant_id=tenant, host_id=params.host_id, action="login_success", size=200, **window)
    logins_after_failures = _logins_after_failures(failures["alerts"], successes["alerts"])

    active, _ = await _incidents_with_summaries(db, tenant_id)
    open_incidents = [
        incident for incident in active
        if incident["status"] in {s.value for s in _ACTIVE_STATUSES} and params.host_id in incident["hosts"]
    ]

    return EndpointSnapshotOutput(
        scope=_scope(f"all alerts on {params.host_id}", params),
        host_id=params.host_id,
        risk_score=endpoint.risk_score if endpoint else None,
        risk_level=endpoint.risk_level if endpoint else None,
        last_scored_at=endpoint.updated_at if endpoint else None,
        recent_alert_count=alerts_result["total"],
        counts=_labeled_counts(alerts_result.get("counts", {})),
        successful_login_after_failures=bool(logins_after_failures),
        same_source_success_after_failures=any(row["failed_attempts_from_same_source"] for row in logins_after_failures),
        logins_after_failures=logins_after_failures,
        open_incidents=open_incidents,
        recent_alerts=alerts_result["alerts"],
        truncated=alerts_result["total"] > len(alerts_result["alerts"]),
    )


async def _top_alerts(db: AsyncSession, tenant_id: uuid.UUID, params: TopAlertsInput) -> AlertListOutput:
    result = await search_alerts(
        tenant_id=str(tenant_id),
        severity=params.severity,
        host_id=params.host_id,
        log_type=params.log_type,
        action=params.action,
        user=params.user,
        size=20,
        sort_by_severity=True,
        aggregate_by=["severity", "log_type"],
        **_window_kwargs(params),
    )
    what = f"{params.severity} alerts" if params.severity else "alerts of every severity"
    scope = _scope(what, params, on=params.host_id, of_type=params.log_type, action=params.action, for_user=params.user)
    return _alert_list_output(result, scope)


async def _user_activity(db: AsyncSession, tenant_id: uuid.UUID, params: UserActivityInput) -> AlertListOutput:
    result = await search_alerts(
        tenant_id=str(tenant_id), user=params.user, size=100,
        aggregate_by=["action", "host_id"], **_window_kwargs(params),
    )
    return _alert_list_output(result, _scope(f"all alerts for account {params.user}", params))


async def _cloud_events(db: AsyncSession, tenant_id: uuid.UUID, params: CloudEventsInput) -> AlertListOutput:
    result = await search_alerts(
        tenant_id=str(tenant_id), source="cloudlens", size=50, aggregate_by=["severity"], **_window_kwargs(params),
    )
    return _alert_list_output(result, _scope("CloudLens cloud findings", params))


async def _risky_endpoints(db: AsyncSession, tenant_id: uuid.UUID, params: RiskyEndpointsInput) -> RiskyEndpointsOutput:
    endpoints = await list_endpoints(db, tenant_id)
    limited = endpoints[: params.limit]
    return RiskyEndpointsOutput(
        endpoints=[_endpoint_to_dict(e) for e in limited],
        truncated=len(endpoints) > len(limited),
    )


async def _attack_chain_status(
    db: AsyncSession, tenant_id: uuid.UUID, params: AttackChainStatusInput
) -> AttackChainStatusOutput:
    incidents, total = await _incidents_with_summaries(db, tenant_id, params.status)
    by_status: dict[str, int] = {}
    for incident in incidents:
        by_status[incident["status"]] = by_status.get(incident["status"], 0) + 1
    active_values = {s.value for s in _ACTIVE_STATUSES}
    return AttackChainStatusOutput(
        total=total,
        active_count=sum(count for status, count in by_status.items() if status in active_values),
        counts={"Incidents by status": by_status} if by_status else {},
        incidents=incidents,
        truncated=total > len(incidents),
    )


_OVERVIEW_TOP_N = 5
_OVERVIEW_CRITICAL_LIMIT = 10


async def _overview(db: AsyncSession, tenant_id: uuid.UUID, params: OverviewInput) -> OverviewOutput:
    tenant = str(tenant_id)
    window = _window_kwargs(params)
    everything = await search_alerts(
        tenant_id=tenant, size=0, aggregate_by=["severity", "log_type"], **window,
    )
    top = await search_alerts(
        tenant_id=tenant, size=0, aggregate_by=["host_id", "user"], aggregate_size=_OVERVIEW_TOP_N, **window,
    )
    critical_high = await search_alerts(
        tenant_id=tenant, severities=["critical", "high"], size=_OVERVIEW_CRITICAL_LIMIT,
        sort_by_severity=True, **window,
    )
    incidents, _ = await _incidents_with_summaries(db, tenant_id)
    active_values = {s.value for s in _ACTIVE_STATUSES}
    active = [
        {key: incident[key] for key in ("category_label", "hosts", "severity", "confidence", "status", "alert_count")}
        for incident in incidents if incident["status"] in active_values
    ]

    counts = _labeled_counts({**everything.get("counts", {}), **top.get("counts", {})})
    return OverviewOutput(
        scope=_scope("all alerts and active incidents", params),
        total_alerts=everything["total"],
        counts=counts,
        critical_high_total=critical_high["total"],
        critical_high_alerts=critical_high["alerts"],
        active_incident_count=len(active),
        active_incidents=active,
        truncated=critical_high["total"] > len(critical_high["alerts"]),
    )


# ── Incident narrative data aggregation (SS-109) ─────────────────────
# Not part of the Intent-dispatch TOOLS registry below: this tool is
# invoked directly by incident_id (services/incident_narrative.py, for
# SS-110's "summarize this incident" action), not resolved from a
# natural-language query like the 8 tools above (SS-044). It follows
# the same typed input/output shape as every other tool here, wrapping
# EXISTING service functions (get_incident_timeline/get_incident_evidence)
# exactly like the rest of this module — no new query logic.

class IncidentNarrativeDataInput(BaseModel):
    incident_id: uuid.UUID


class TimelineEventSummary(BaseModel):
    type: str
    timestamp: datetime
    data: dict


class IncidentNarrativeDataOutput(BaseModel):
    incident_id: uuid.UUID
    events: list[TimelineEventSummary]
    hosts: list[dict]
    ips: list[dict]
    users: list[dict]
    cloud_resources: list[dict]
    mitre_techniques: list[str]
    confidence: Optional[float] = None


async def incident_narrative_data(
    db: AsyncSession, tenant_id: uuid.UUID, params: IncidentNarrativeDataInput
) -> IncidentNarrativeDataOutput:
    """
    Raises:
        IncidentNotFoundError: via get_incident (also enforces tenant
        scoping before any data is gathered).
    """
    incident = await get_incident(db, tenant_id, params.incident_id)
    timeline = await get_incident_timeline(db, tenant_id, params.incident_id)
    evidence = await get_incident_evidence(db, tenant_id, params.incident_id)

    # Both MITRE sources, not just the alert-level one: synthetic
    # alerts carry no mitre_technique at all, which left every view
    # built on this tool (AI narrative, investigation session, the
    # "Known evidence" box) reporting no techniques for an incident
    # Threat Analytics showed techniques for.
    mitre_techniques = incident_technique_ids(
        (entry.data.get("mitre_technique") for entry in timeline if entry.type == "alert"),
        incident.category,
    )

    return IncidentNarrativeDataOutput(
        incident_id=incident.id,
        events=[TimelineEventSummary(type=entry.type, timestamp=entry.timestamp, data=entry.data) for entry in timeline],
        hosts=[host.model_dump(mode="json") for host in evidence.hosts],
        # ti (per-provider threat-intel detail) is for the Evidence UI;
        # left out so this tool's LLM-facing payload stays compact.
        ips=[ip.model_dump(mode="json", exclude={"ti"}) for ip in evidence.ips],
        users=[user.model_dump(mode="json") for user in evidence.users],
        cloud_resources=[resource.model_dump(mode="json") for resource in evidence.cloud_resources],
        mitre_techniques=mitre_techniques,
        confidence=incident.confidence,
    )


@dataclass(frozen=True)
class MCPTool:
    intent: Intent
    name: str
    description: str
    input_model: type[BaseModel]
    output_model: type[BaseModel]
    handler: Callable[[AsyncSession, uuid.UUID, BaseModel], Awaitable[BaseModel]]

    async def call(self, db: AsyncSession, tenant_id: uuid.UUID, raw_params: dict) -> BaseModel:
        """Validate raw_params against this tool's input schema, then invoke its handler."""
        params = self.input_model(**raw_params)
        return await self.handler(db, tenant_id, params)


TOOLS: dict[Intent, MCPTool] = {
    Intent.AUTH_FAILURES: MCPTool(
        intent=Intent.AUTH_FAILURES,
        name="auth_failures",
        description="Failed logins, optionally for one host and/or account, with counts by source IP, account and host.",
        input_model=AuthFailuresInput,
        output_model=AlertListOutput,
        handler=_auth_failures,
    ),
    Intent.IP_ACTIVITY: MCPTool(
        intent=Intent.IP_ACTIVITY,
        name="ip_activity",
        description="All alerts with the IP as source or destination, with counts by host, account and activity.",
        input_model=IPActivityInput,
        output_model=AlertListOutput,
        handler=_ip_activity,
    ),
    Intent.ENDPOINT_SNAPSHOT: MCPTool(
        intent=Intent.ENDPOINT_SNAPSHOT,
        name="endpoint_snapshot",
        description="One host: risk score, all its alerts with counts by activity and severity, logins that succeeded after failures, and its open incidents.",
        input_model=EndpointSnapshotInput,
        output_model=EndpointSnapshotOutput,
        handler=_endpoint_snapshot,
    ),
    Intent.TOP_ALERTS: MCPTool(
        intent=Intent.TOP_ALERTS,
        name="top_alerts",
        description="Alerts sorted by severity then time, filterable by severity/host/log type/action/account, with counts by severity and log type.",
        input_model=TopAlertsInput,
        output_model=AlertListOutput,
        handler=_top_alerts,
    ),
    Intent.USER_ACTIVITY: MCPTool(
        intent=Intent.USER_ACTIVITY,
        name="user_activity",
        description="All alerts for one account, with counts by activity and host.",
        input_model=UserActivityInput,
        output_model=AlertListOutput,
        handler=_user_activity,
    ),
    Intent.CLOUD_EVENTS: MCPTool(
        intent=Intent.CLOUD_EVENTS,
        name="cloud_events",
        description="List CloudLens-sourced cloud security findings.",
        input_model=CloudEventsInput,
        output_model=AlertListOutput,
        handler=_cloud_events,
    ),
    Intent.RISKY_ENDPOINTS: MCPTool(
        intent=Intent.RISKY_ENDPOINTS,
        name="risky_endpoints",
        description="Known endpoints sorted by risk score descending.",
        input_model=RiskyEndpointsInput,
        output_model=RiskyEndpointsOutput,
        handler=_risky_endpoints,
    ),
    Intent.ATTACK_CHAIN_STATUS: MCPTool(
        intent=Intent.ATTACK_CHAIN_STATUS,
        name="attack_chain_status",
        description="Incidents (detected attack chains) with category, hosts, severity, confidence, MITRE techniques and status.",
        input_model=AttackChainStatusInput,
        output_model=AttackChainStatusOutput,
        handler=_attack_chain_status,
    ),
}

TOOLS[Intent.OVERVIEW] = MCPTool(
    intent=Intent.OVERVIEW,
    name="overview",
    description="Tenant-wide overview for a window: counts by severity and log type, top hosts and targeted accounts, critical/high alerts, and active incidents.",
    input_model=OverviewInput,
    output_model=OverviewOutput,
    handler=_overview,
)
