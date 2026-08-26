"""
SafeSOC — Incident Evidence Extraction
Given an incident's alert_ids, extracts the distinct entities involved
(hosts, IPs, users, cloud resources) and annotates them with data
already computed elsewhere — Endpoint risk scores (SS-032/033) for
hosts, ti_cache verdicts (SS-024) for IPs — so an analyst sees "who/
what was involved" at a glance instead of re-deriving it by reading
every linked alert (SS-100).

One shared extraction/annotation path, meant to be reused by both the
existing chat evidence panel (SS-083, which today just renders a raw
tool_result) and the upcoming incident Evidence Explorer (SS-101), so
the two views can't drift apart.

Degrades gracefully throughout: a host with no Endpoint row yet, or an
IP with no ti_cache entry, simply carries a null annotation rather
than failing extraction for the whole incident.
"""

import uuid
from typing import Optional

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import LogSource, RiskLevel
from app.db.opensearch import get_alerts_by_ids
from app.models.endpoint import Endpoint
from app.models.ti_cache import TICache
from app.services.incidents import get_incident


class HostEntity(BaseModel):
    host_id: str
    host_os: Optional[str] = None
    risk_score: Optional[int] = None
    risk_level: Optional[RiskLevel] = None
    alert_count: int


class IPEntity(BaseModel):
    ip: str
    # "source" and/or "destination" — which role(s) this IP played
    # across the incident's alerts.
    roles: list[str]
    # None = never checked against threat intel (no ti_cache row at
    # all); True/False = the cached verdict, malicious if ANY provider
    # flagged it.
    is_malicious: Optional[bool] = None
    alert_count: int


class UserEntity(BaseModel):
    user: str
    alert_count: int


class CloudResourceEntity(BaseModel):
    resource_id: str
    alert_count: int


class IncidentEvidence(BaseModel):
    incident_id: uuid.UUID
    hosts: list[HostEntity]
    ips: list[IPEntity]
    users: list[UserEntity]
    cloud_resources: list[CloudResourceEntity]


async def _endpoint_risk_by_host(db: AsyncSession, tenant_id: uuid.UUID, host_ids: list[str]) -> dict[str, Endpoint]:
    if not host_ids:
        return {}
    result = await db.execute(select(Endpoint).where(Endpoint.tenant_id == tenant_id, Endpoint.host_id.in_(host_ids)))
    return {endpoint.host_id: endpoint for endpoint in result.scalars().all()}


async def _ti_verdicts(db: AsyncSession, indicators: list[str]) -> dict[str, bool]:
    if not indicators:
        return {}
    result = await db.execute(select(TICache).where(TICache.indicator.in_(indicators)))
    verdicts: dict[str, bool] = {}
    for row in result.scalars().all():
        # If any cached provider says malicious, the indicator is
        # malicious; otherwise clean, as long as at least one provider
        # has actually checked it (rows for this indicator exist).
        verdicts[row.indicator] = verdicts.get(row.indicator, False) or row.is_malicious
    return verdicts


async def get_incident_evidence(db: AsyncSession, tenant_id: uuid.UUID, incident_id: uuid.UUID) -> IncidentEvidence:
    """
    Raises:
        IncidentNotFoundError: via get_incident — also enforces the
        incident belongs to this tenant before any data is gathered.
    """
    incident = await get_incident(db, tenant_id, incident_id)
    alerts = await get_alerts_by_ids(incident.alert_ids)

    host_os: dict[str, Optional[str]] = {}
    host_alert_counts: dict[str, int] = {}
    cloud_alert_counts: dict[str, int] = {}
    ip_roles: dict[str, set[str]] = {}
    ip_alert_counts: dict[str, int] = {}
    user_alert_counts: dict[str, int] = {}

    for alert in alerts:
        host_id = alert.get("host_id")
        if host_id:
            # A CloudLens-sourced alert's host_id holds the affected
            # cloud resource identifier, not a real host (SS-038's
            # adapter maps Finding.affected_resource -> host_id) — so
            # it's a distinct entity type, not a "host".
            if alert.get("source") == LogSource.CLOUDLENS.value:
                cloud_alert_counts[host_id] = cloud_alert_counts.get(host_id, 0) + 1
            else:
                host_alert_counts[host_id] = host_alert_counts.get(host_id, 0) + 1
                if alert.get("host_os"):
                    host_os[host_id] = alert["host_os"]

        for field, role in (("source_ip", "source"), ("destination_ip", "destination")):
            ip = alert.get(field)
            if ip:
                ip_roles.setdefault(ip, set()).add(role)
                ip_alert_counts[ip] = ip_alert_counts.get(ip, 0) + 1

        user = alert.get("user")
        if user and user != "unknown":
            user_alert_counts[user] = user_alert_counts.get(user, 0) + 1

    endpoints = await _endpoint_risk_by_host(db, tenant_id, list(host_alert_counts))
    ti_verdicts = await _ti_verdicts(db, list(ip_roles))

    hosts = [
        HostEntity(
            host_id=host_id,
            host_os=host_os.get(host_id),
            risk_score=endpoints[host_id].risk_score if host_id in endpoints else None,
            risk_level=endpoints[host_id].risk_level if host_id in endpoints else None,
            alert_count=count,
        )
        for host_id, count in host_alert_counts.items()
    ]

    ips = [
        IPEntity(ip=ip, roles=sorted(roles), is_malicious=ti_verdicts.get(ip), alert_count=ip_alert_counts[ip])
        for ip, roles in ip_roles.items()
    ]

    users = [UserEntity(user=user, alert_count=count) for user, count in user_alert_counts.items()]

    cloud_resources = [
        CloudResourceEntity(resource_id=resource_id, alert_count=count)
        for resource_id, count in cloud_alert_counts.items()
    ]

    return IncidentEvidence(incident_id=incident.id, hosts=hosts, ips=ips, users=users, cloud_resources=cloud_resources)
