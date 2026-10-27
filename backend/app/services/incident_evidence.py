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

import ipaddress
import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.enums import LogSource, RiskLevel, TIProvider
from app.db.opensearch import get_alerts_by_ids
from app.models.endpoint import Endpoint
from app.models.ti_cache import TICache
from app.schemas.log import AbuseIPDetails, TIResult, VTIPDetails
from app.services.incidents import get_incident


class HostEntity(BaseModel):
    host_id: str
    host_os: Optional[str] = None
    risk_score: Optional[int] = None
    risk_level: Optional[RiskLevel] = None
    alert_count: int
    # SS-103: true if any alert tied to this host had an anomaly_score
    # (SS-102) at or above settings.ANOMALY_THRESHOLD — the same
    # threshold services/anomaly.py itself uses to decide is_anomalous,
    # not a new one invented here.
    has_anomalous_activity: bool = False


class IPThreatIntel(BaseModel):
    """
    Everything ti_cache holds for one IP: the combined verdict plus each
    provider's own details, read only from that provider's row.
    """
    is_malicious: bool
    # Latest created_at across this IP's ti_cache rows.
    checked_at: Optional[datetime] = None
    vt: Optional[VTIPDetails] = None
    abuse: Optional[AbuseIPDetails] = None


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
    # None = no ti_cache row at all (same condition as is_malicious None).
    ti: Optional[IPThreatIntel] = None
    # Globally routable — False for private/reserved/documentation
    # ranges (never looked up meaningfully) and for unparseable values.
    is_public: bool = False


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


def _is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _cached_result(row: TICache) -> Optional[TIResult]:
    try:
        return TIResult(**(row.result or {}))
    except (TypeError, ValidationError):
        return None


async def _ti_intel(db: AsyncSession, indicators: list[str]) -> dict[str, IPThreatIntel]:
    """
    Per-IP threat intel from ti_cache. "Checked" means at least one row
    exists for the indicator, from any provider, expired or not — the
    same rule as services/enrichment.py::has_ti_data, so this panel and
    SOAR's ENRICH_INDICATOR never disagree about what was checked.
    """
    if not indicators:
        return {}
    result = await db.execute(select(TICache).where(TICache.indicator.in_(indicators)))
    intel: dict[str, IPThreatIntel] = {}
    for row in result.scalars().all():
        entry = intel.setdefault(row.indicator, IPThreatIntel(is_malicious=False))
        # If any cached provider says malicious, the indicator is
        # malicious; otherwise clean.
        entry.is_malicious = entry.is_malicious or row.is_malicious
        if row.created_at is not None and (entry.checked_at is None or row.created_at > entry.checked_at):
            entry.checked_at = row.created_at
        cached = _cached_result(row)
        if cached is None:
            continue
        if row.provider == TIProvider.VIRUSTOTAL:
            entry.vt = cached.vt
        elif row.provider == TIProvider.ABUSEIPDB:
            entry.abuse = cached.abuse
    return intel


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
    host_has_anomaly: dict[str, bool] = {}
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
                anomaly_score = alert.get("anomaly_score")
                if anomaly_score is not None and anomaly_score >= settings.ANOMALY_THRESHOLD:
                    host_has_anomaly[host_id] = True

        for field, role in (("source_ip", "source"), ("destination_ip", "destination")):
            ip = alert.get(field)
            if ip:
                ip_roles.setdefault(ip, set()).add(role)
                ip_alert_counts[ip] = ip_alert_counts.get(ip, 0) + 1

        user = alert.get("user")
        if user and user != "unknown":
            user_alert_counts[user] = user_alert_counts.get(user, 0) + 1

    endpoints = await _endpoint_risk_by_host(db, tenant_id, list(host_alert_counts))
    ti_intel = await _ti_intel(db, list(ip_roles))

    hosts = [
        HostEntity(
            host_id=host_id,
            host_os=host_os.get(host_id),
            risk_score=endpoints[host_id].risk_score if host_id in endpoints else None,
            risk_level=endpoints[host_id].risk_level if host_id in endpoints else None,
            alert_count=count,
            has_anomalous_activity=host_has_anomaly.get(host_id, False),
        )
        for host_id, count in host_alert_counts.items()
    ]

    ips = [
        IPEntity(
            ip=ip,
            roles=sorted(roles),
            is_malicious=ti_intel[ip].is_malicious if ip in ti_intel else None,
            alert_count=ip_alert_counts[ip],
            ti=ti_intel.get(ip),
            is_public=_is_public(ip),
        )
        for ip, roles in ip_roles.items()
    ]

    users = [UserEntity(user=user, alert_count=count) for user, count in user_alert_counts.items()]

    cloud_resources = [
        CloudResourceEntity(resource_id=resource_id, alert_count=count)
        for resource_id, count in cloud_alert_counts.items()
    ]

    return IncidentEvidence(incident_id=incident.id, hosts=hosts, ips=ips, users=users, cloud_resources=cloud_resources)
