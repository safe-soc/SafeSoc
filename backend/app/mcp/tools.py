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
from datetime import datetime
from typing import Awaitable, Callable, Optional

from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Intent, IncidentStatus, RiskLevel
from app.core.mitre_mapping import incident_technique_ids
from app.db.opensearch import search_alerts
from app.models.endpoint import Endpoint
from app.models.incident import Incident
from app.services.incident_evidence import get_incident_evidence
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


def _incident_to_dict(incident: Incident) -> dict:
    return {
        "id": str(incident.id),
        "status": incident.status.value,
        "alert_ids": incident.alert_ids,
        "created_at": incident.created_at.isoformat(),
        "updated_at": incident.updated_at.isoformat(),
    }


def _alert_list_output(result: dict) -> "AlertListOutput":
    """
    Shared by every tool backed by search_alerts (SS-086). `result["total"]`
    is a genuine full-match count (search_alerts sets track_total_hits),
    while `result["alerts"]` is capped by the `size` each tool queries
    with — so truncation is always knowable by comparing the two,
    without any extra query.
    """
    return AlertListOutput(
        total=result["total"],
        alerts=result["alerts"],
        truncated=result["total"] > len(result["alerts"]),
    )


# ── Input/output schemas (one pair per intent) ────────────────────

class AuthFailuresInput(BaseModel):
    host_id: Optional[str] = None
    timerange_hours: int = 24


class IPActivityInput(BaseModel):
    ip: str
    timerange_hours: int = 24


class EndpointSnapshotInput(BaseModel):
    host_id: str


class TopAlertsInput(BaseModel):
    severity: Optional[str] = None
    timerange_hours: int = 24


class UserActivityInput(BaseModel):
    user: str
    timerange_hours: int = 24


class CloudEventsInput(BaseModel):
    timerange_hours: int = 24


class RiskyEndpointsInput(BaseModel):
    limit: int = 10


class AttackChainStatusInput(BaseModel):
    status: Optional[IncidentStatus] = None


class AlertListOutput(BaseModel):
    total: int
    alerts: list[dict]
    # True when `total` exceeds len(alerts) — i.e. this tool's own size
    # cap left out real matches (SS-086). Defaults False so any other
    # construction site (e.g. existing tests) keeps prior behavior.
    truncated: bool = False


class EndpointSnapshotOutput(BaseModel):
    host_id: str
    risk_score: Optional[int] = None
    risk_level: Optional[RiskLevel] = None
    last_scored_at: Optional[datetime] = None
    recent_alert_count: int
    recent_alerts: list[dict]
    truncated: bool = False


class RiskyEndpointsOutput(BaseModel):
    endpoints: list[dict]
    truncated: bool = False


class AttackChainStatusOutput(BaseModel):
    total: int
    incidents: list[dict]
    truncated: bool = False


# ── Tool handlers ──────────────────────────────────────────────────
# Every handler takes the same (db, tenant_id, params) shape, even
# though OpenSearch-only tools don't need `db` — a uniform calling
# convention keeps the orchestration layer (SS-046/SS-047) simple,
# with no per-tool special-casing needed to invoke one.

async def _auth_failures(db: AsyncSession, tenant_id: uuid.UUID, params: AuthFailuresInput) -> AlertListOutput:
    result = await search_alerts(
        tenant_id=str(tenant_id),
        action="failed_login",
        host_id=params.host_id,
        timerange_hours=params.timerange_hours,
        size=100,
    )
    return _alert_list_output(result)


async def _ip_activity(db: AsyncSession, tenant_id: uuid.UUID, params: IPActivityInput) -> AlertListOutput:
    result = await search_alerts(
        tenant_id=str(tenant_id), source_ip=params.ip, timerange_hours=params.timerange_hours, size=100
    )
    return _alert_list_output(result)


async def _endpoint_snapshot(
    db: AsyncSession, tenant_id: uuid.UUID, params: EndpointSnapshotInput
) -> EndpointSnapshotOutput:
    endpoint = await get_endpoint(db, tenant_id, params.host_id)
    alerts_result = await search_alerts(tenant_id=str(tenant_id), host_id=params.host_id, timerange_hours=24, size=20)

    return EndpointSnapshotOutput(
        host_id=params.host_id,
        risk_score=endpoint.risk_score if endpoint else None,
        risk_level=endpoint.risk_level if endpoint else None,
        last_scored_at=endpoint.updated_at if endpoint else None,
        recent_alert_count=alerts_result["total"],
        recent_alerts=alerts_result["alerts"],
        truncated=alerts_result["total"] > len(alerts_result["alerts"]),
    )


async def _top_alerts(db: AsyncSession, tenant_id: uuid.UUID, params: TopAlertsInput) -> AlertListOutput:
    result = await search_alerts(
        tenant_id=str(tenant_id), severity=params.severity, timerange_hours=params.timerange_hours, size=20
    )
    return _alert_list_output(result)


async def _user_activity(db: AsyncSession, tenant_id: uuid.UUID, params: UserActivityInput) -> AlertListOutput:
    result = await search_alerts(
        tenant_id=str(tenant_id), user=params.user, timerange_hours=params.timerange_hours, size=100
    )
    return _alert_list_output(result)


async def _cloud_events(db: AsyncSession, tenant_id: uuid.UUID, params: CloudEventsInput) -> AlertListOutput:
    result = await search_alerts(
        tenant_id=str(tenant_id), source="cloudlens", timerange_hours=params.timerange_hours, size=50
    )
    return _alert_list_output(result)


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
    incidents, total = await list_incidents(db, tenant_id, status=params.status)
    return AttackChainStatusOutput(
        total=total,
        incidents=[_incident_to_dict(i) for i in incidents],
        truncated=total > len(incidents),
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
        description="List failed login/authentication alerts, optionally scoped to one host.",
        input_model=AuthFailuresInput,
        output_model=AlertListOutput,
        handler=_auth_failures,
    ),
    Intent.IP_ACTIVITY: MCPTool(
        intent=Intent.IP_ACTIVITY,
        name="ip_activity",
        description="List alerts whose source IP matches the given address.",
        input_model=IPActivityInput,
        output_model=AlertListOutput,
        handler=_ip_activity,
    ),
    Intent.ENDPOINT_SNAPSHOT: MCPTool(
        intent=Intent.ENDPOINT_SNAPSHOT,
        name="endpoint_snapshot",
        description="Current risk score/level plus recent alerts for a single host.",
        input_model=EndpointSnapshotInput,
        output_model=EndpointSnapshotOutput,
        handler=_endpoint_snapshot,
    ),
    Intent.TOP_ALERTS: MCPTool(
        intent=Intent.TOP_ALERTS,
        name="top_alerts",
        description="Most recent alerts, optionally filtered by severity.",
        input_model=TopAlertsInput,
        output_model=AlertListOutput,
        handler=_top_alerts,
    ),
    Intent.USER_ACTIVITY: MCPTool(
        intent=Intent.USER_ACTIVITY,
        name="user_activity",
        description="List alerts attributed to a given user.",
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
        description="Incidents (correlation-chain results), optionally filtered by status.",
        input_model=AttackChainStatusInput,
        output_model=AttackChainStatusOutput,
        handler=_attack_chain_status,
    ),
}

# OVERVIEW ("anything suspicious today?") has no dedicated tool yet:
# it runs the top-alerts query until one exists, so every intent dispatches.
TOOLS[Intent.OVERVIEW] = MCPTool(
    intent=Intent.OVERVIEW,
    name="overview",
    description="Tenant-wide overview — currently the most recent alerts, optionally filtered by severity.",
    input_model=TopAlertsInput,
    output_model=AlertListOutput,
    handler=_top_alerts,
)
