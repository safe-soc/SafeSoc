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

from app.core.enums import CorrelationPattern, Intent, IncidentStatus, RiskLevel
from app.core.mitre_mapping import incident_technique_ids
from app.db.opensearch import get_alerts_by_ids, search_alerts
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
_ACTIVE_STATUS_VALUES = frozenset(status.value for status in _ACTIVE_STATUSES)
# How many incidents a status-wide listing considers; more than any
# tenant's open set in practice, and the response reports the true total.
_INCIDENT_LIST_LIMIT = 100


async def _incidents_with_summaries(
    db: AsyncSession, tenant_id: uuid.UUID,
    status: Optional[IncidentStatus] = None, category: Optional[CorrelationPattern] = None,
) -> tuple[list[tuple[Incident, dict]], int]:
    """Incidents with their model-facing dicts, from ONE batched alert lookup (services/incident_summary.py)."""
    incidents, total = await list_incidents(db, tenant_id, status=status, size=_INCIDENT_LIST_LIMIT, category=category)
    summaries = await summarize_incidents(incidents)
    return [(incident, _incident_to_dict(incident, summaries.get(incident.id))) for incident in incidents], total


# ── What was searched, in words ─────────────────────────────────────
# Every alert-backed result carries `subject` ("failed logins for
# john.doe on UBUNTU-WEB-01 in the last 24 hours") and `scope`
# ("Searched <subject>."). The model must state the scope and never
# claim absence outside it; the router builds the zero-result sentence
# ("No <subject>.") and the templated fallback from the same words.

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


def _subject(what: str, params: "_Window", *qualifiers: Optional[str]) -> str:
    """"<what> <qualifiers…> <window>" — qualifiers are pre-phrased ("for john.doe", "on WIN10-FIN-07") or None."""
    return " ".join([what, *(q for q in qualifiers if q), _window_text(params)])


def _scope(subject: str) -> str:
    return f"Searched {subject}."


def _window_kwargs(params: "_Window") -> dict:
    return {"timerange_hours": params.timerange_hours, "start": params.start, "end": params.end}


def _when(prefix: str, value: Optional[str]) -> Optional[str]:
    return f"{prefix} {value}" if value else None


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
    """
    Real totals: these come from OpenSearch terms aggregations over the
    WHOLE match set (search_alerts' aggregate_by), never from the sample
    rows a tool returns.
    """
    labeled = {}
    for field, values in counts.items():
        if field == "user":
            # "unknown" is the ingestion placeholder, not an account.
            values = {name: count for name, count in values.items() if name.lower() != "unknown"}
        if values:
            labeled[_COUNT_LABELS.get(field, field)] = values
    return labeled


def _alert_list_output(result: dict, subject: str = "") -> "AlertListOutput":
    """
    Shared by every tool backed by search_alerts (SS-086). `result["total"]`
    is a genuine full-match count (search_alerts sets track_total_hits),
    while `result["alerts"]` is capped by the `size` each tool queries
    with — so truncation is always knowable by comparing the two,
    without any extra query.
    """
    return AlertListOutput(
        subject=subject,
        scope=_scope(subject) if subject else "",
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
    # None = not asked; the tool then shows _DEFAULT_RISKY_LIMIT.
    limit: Optional[int] = Field(None, ge=1, le=50)


class AttackChainStatusInput(BaseModel):
    status: Optional[IncidentStatus] = None
    category: Optional[CorrelationPattern] = None


class OverviewInput(_Window):
    pass


class AlertListOutput(BaseModel):
    # What was searched: `subject` in words, `scope` as the sentence the
    # model must lead with.
    subject: str = ""
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
    subject: str = ""
    scope: str = ""
    host_id: str
    risk_score: Optional[int] = None
    risk_level: Optional[RiskLevel] = None
    last_scored_at: Optional[datetime] = None
    recent_alert_count: int
    counts: dict[str, dict[str, int]] = {}
    # The "did they get in?" signal: a login_success on this host after
    # failed_login attempts on it — the same host-level sequence the
    # correlation engine's successful_compromise pattern detects. Also
    # true while the host has an open successful_compromise incident.
    successful_login_after_failures: bool = False
    # Stronger: the success came from a source IP that had itself failed.
    same_source_success_after_failures: bool = False
    # An open/investigating "Successful compromise" incident on this host.
    compromise_incident_open: bool = False
    logins_after_failures: list[dict] = []
    open_incidents: list[dict] = []
    recent_alerts: list[dict]
    truncated: bool = False


class RiskyEndpointsOutput(BaseModel):
    endpoints: list[dict]
    # True only when the analyst didn't ask for a number and the default
    # cap left endpoints out — "top 3" returning 3 is complete.
    truncated: bool = False


class AttackChainStatusOutput(BaseModel):
    subject: str = ""
    scope: str = ""
    total: int
    # Incidents are detected attack chains; open + investigating = active.
    active_count: int = 0
    counts: dict[str, dict[str, int]] = {}
    incidents: list[dict]
    truncated: bool = False


class OverviewOutput(BaseModel):
    subject: str = ""
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
        aggregate_by=["source_ip", "user", "host_id", "severity"],
        **_window_kwargs(params),
    )
    subject = _subject("failed logins", params, _when("for", params.user), _when("on", params.host_id))
    return _alert_list_output(result, subject)


async def _ip_activity(db: AsyncSession, tenant_id: uuid.UUID, params: IPActivityInput) -> AlertListOutput:
    result = await search_alerts(
        tenant_id=str(tenant_id), ip=params.ip, size=100,
        aggregate_by=["host_id", "user", "action", "severity"], **_window_kwargs(params),
    )
    return _alert_list_output(result, _subject(f"alerts involving {params.ip} (as source or destination)", params))


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


async def _compromise_incident_logins(host_id: str, incidents: list[Incident]) -> list[dict]:
    """
    Login-success-after-failures evaluated over open "Successful
    compromise" incidents' OWN alerts (one batched lookup) — the alerts
    the correlation engine actually matched, which may fall outside the
    searched window. Keeps the snapshot consistent with the incident.
    """
    alert_ids = sorted({alert_id for incident in incidents for alert_id in incident.alert_ids})
    if not alert_ids:
        return []
    alerts = [alert for alert in await get_alerts_by_ids(alert_ids) if alert.get("host_id") == host_id]
    failures = [alert for alert in alerts if alert.get("action") == "failed_login"]
    successes = [alert for alert in alerts if alert.get("action") == "login_success"]
    return _logins_after_failures(failures, successes)


async def _endpoint_snapshot(
    db: AsyncSession, tenant_id: uuid.UUID, params: EndpointSnapshotInput
) -> EndpointSnapshotOutput:
    tenant = str(tenant_id)
    endpoint = await get_endpoint(db, tenant_id, params.host_id)
    window = _window_kwargs(params)
    # Every alert type for this host, not just failures.
    alerts_result = await search_alerts(
        tenant_id=tenant, host_id=params.host_id, size=20,
        aggregate_by=["action", "severity", "user", "source_ip"], **window,
    )
    failures = await search_alerts(tenant_id=tenant, host_id=params.host_id, action="failed_login", size=200, **window)
    successes = await search_alerts(tenant_id=tenant, host_id=params.host_id, action="login_success", size=200, **window)
    logins_after_failures = _logins_after_failures(failures["alerts"], successes["alerts"])

    # The host's open incidents are always included, whatever the window.
    rows, _ = await _incidents_with_summaries(db, tenant_id)
    on_host = [
        (incident, data) for incident, data in rows
        if data["status"] in _ACTIVE_STATUS_VALUES and params.host_id in data["hosts"]
    ]
    compromise = [incident for incident, _ in on_host if incident.category == CorrelationPattern.SUCCESSFUL_COMPROMISE]
    if compromise:
        seen = {(row["success_at"], row["source_ip"]) for row in logins_after_failures}
        for row in await _compromise_incident_logins(params.host_id, compromise):
            if (row["success_at"], row["source_ip"]) not in seen:
                logins_after_failures.append(row)

    subject = _subject(f"alerts on {params.host_id}", params)
    return EndpointSnapshotOutput(
        subject=subject,
        scope=_scope(subject),
        host_id=params.host_id,
        risk_score=endpoint.risk_score if endpoint else None,
        risk_level=endpoint.risk_level if endpoint else None,
        last_scored_at=endpoint.updated_at if endpoint else None,
        recent_alert_count=alerts_result["total"],
        counts=_labeled_counts(alerts_result.get("counts", {})),
        successful_login_after_failures=bool(logins_after_failures) or bool(compromise),
        same_source_success_after_failures=any(row["failed_attempts_from_same_source"] for row in logins_after_failures),
        compromise_incident_open=bool(compromise),
        logins_after_failures=logins_after_failures,
        open_incidents=[data for _, data in on_host],
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
        aggregate_by=["severity", "log_type", "host_id", "user"],
        **_window_kwargs(params),
    )
    what = f"{params.severity} alerts" if params.severity else "alerts"
    subject = _subject(
        what, params, _when("of type", params.log_type), _when("with activity", params.action),
        _when("for", params.user), _when("on", params.host_id),
    )
    return _alert_list_output(result, subject)


async def _user_activity(db: AsyncSession, tenant_id: uuid.UUID, params: UserActivityInput) -> AlertListOutput:
    result = await search_alerts(
        tenant_id=str(tenant_id), user=params.user, size=100,
        aggregate_by=["action", "host_id", "severity", "source_ip"], **_window_kwargs(params),
    )
    return _alert_list_output(result, _subject(f"alerts for account {params.user}", params))


async def _cloud_events(db: AsyncSession, tenant_id: uuid.UUID, params: CloudEventsInput) -> AlertListOutput:
    result = await search_alerts(
        tenant_id=str(tenant_id), source="cloudlens", size=50, aggregate_by=["severity", "host_id"], **_window_kwargs(params),
    )
    return _alert_list_output(result, _subject("CloudLens cloud findings", params))


_DEFAULT_RISKY_LIMIT = 10


async def _risky_endpoints(db: AsyncSession, tenant_id: uuid.UUID, params: RiskyEndpointsInput) -> RiskyEndpointsOutput:
    endpoints = await list_endpoints(db, tenant_id)
    limit = params.limit or _DEFAULT_RISKY_LIMIT
    limited = endpoints[:limit]
    return RiskyEndpointsOutput(
        endpoints=[_endpoint_to_dict(e) for e in limited],
        # "Top 3" returning 3 is what was asked for, not a partial result.
        truncated=params.limit is None and len(endpoints) > len(limited),
    )


async def _attack_chain_status(
    db: AsyncSession, tenant_id: uuid.UUID, params: AttackChainStatusInput
) -> AttackChainStatusOutput:
    rows, total = await _incidents_with_summaries(db, tenant_id, params.status, params.category)
    incidents = [data for _, data in rows]
    by_status: dict[str, int] = {}
    for incident in incidents:
        by_status[incident["status"]] = by_status.get(incident["status"], 0) + 1
    parts = ["incidents"]
    if params.category:
        parts.append(f"of pattern {category_label(params.category)}")
    if params.status:
        parts.append(f"with status {params.status.value}")
    subject = " ".join(parts)
    return AttackChainStatusOutput(
        subject=subject,
        scope=_scope(subject),
        total=total,
        active_count=sum(count for status, count in by_status.items() if status in _ACTIVE_STATUS_VALUES),
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
    rows, _ = await _incidents_with_summaries(db, tenant_id)
    active = [
        {key: data[key] for key in ("category_label", "hosts", "severity", "confidence", "status", "alert_count")}
        for _, data in rows if data["status"] in _ACTIVE_STATUS_VALUES
    ]

    subject = _subject("alerts", params)
    return OverviewOutput(
        subject=subject,
        scope=_scope(f"{subject} and active incidents"),
        total_alerts=everything["total"],
        counts=_labeled_counts({**everything.get("counts", {}), **top.get("counts", {})}),
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
        ips=[ip.model_dump(mode="json") for ip in evidence.ips],
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
