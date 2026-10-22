"""
SafeSOC — Threat Analytics Rollup
Org-wide trend view of detected activity (SS-111): aggregates
correlation-pattern triggers across a tenant's incidents over a
rolling window, comparing the current window against the equal-length
window immediately before it (e.g. "Credential Access attempts
trending up 40% this week").

Explicitly a rollup of existing detection data, not a new CTI feed:
reuses Incident.category (SS-094, already populated by the
correlation engine at detection time), the existing static MITRE
ATT&CK pattern mapping (core/mitre_mapping.py, SS-029), and — for
everything below the category trend (KPIs, incident trend, status/
severity, MITRE technique tally, affected assets) — a single batched
OpenSearch lookup of every alert linked to a current-window incident
(db.opensearch.get_alerts_by_ids, the same primitive
incident_evidence.py/investigation_report.py already use per-incident,
here fetched once for the whole window instead of N times).

Incident rows carry no `severity` column (see models/incident.py's own
note on why) — severity, host, and user are derived from each
incident's real linked alerts, never guessed; an incident whose alerts
can't be resolved (e.g. pruned by OpenSearch ILM retention) is simply
excluded from severity-based aggregates rather than defaulted to a
number that isn't real.
"""

import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CorrelationPattern, IncidentStatus, LogSource, RiskLevel, Severity
from app.core.mitre_mapping import get_mitre_technique, split_technique_ids
from app.db.opensearch import get_alerts_by_ids
from app.models.endpoint import Endpoint
from app.models.incident import Incident

# Manually-created incidents (services/incidents.py:create_incident)
# have no detected chain, so category is null — excluded from the
# category-trend rollup entirely, same as everywhere else category is
# null-checked. They still count toward every other section below
# (KPIs, trend, status/severity, affected assets) since those are
# derived from real linked alerts, not from category.
_DEFAULT_WINDOW_DAYS = 7
_SEVERITY_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}
_MITRE_TECHNIQUE_LIMIT = 10
_MITRE_DETAIL_LIMIT = 10
_AFFECTED_ASSET_LIMIT = 10


class CategoryTrend(BaseModel):
    category: CorrelationPattern
    mitre_tactic: str
    mitre_technique_ids: list[str]
    current_count: int
    previous_count: int
    # None when previous_count is 0 — percentage change is undefined,
    # not infinite/zero, when there was nothing to compare against.
    change_pct: Optional[float] = None


class ThreatAnalyticsKPIs(BaseModel):
    total_incidents: int
    open_incidents: int
    critical_high_incidents: int
    # Incidents in the window whose severity couldn't be determined —
    # none of their linked alert_ids resolved to a real alert document.
    # Surfaced rather than hidden, so critical_high_incidents is never
    # mistaken for "out of total_incidents" when this is nonzero.
    incidents_with_unknown_severity: int
    affected_endpoints: int
    affected_users: int
    detection_categories: int


class DailyIncidentCount(BaseModel):
    date: str  # YYYY-MM-DD, UTC
    count: int


class StatusCount(BaseModel):
    status: IncidentStatus
    count: int


class SeverityCount(BaseModel):
    severity: Severity
    count: int


class MitreTechniqueCount(BaseModel):
    technique_id: str
    # None when no alert carrying this technique also carried a tactic
    # string — never guessed from the technique ID.
    tactic: Optional[str] = None
    incident_count: int
    # Capped, real ids/hosts only — never a fabricated "N more" placeholder.
    related_incident_ids: list[str] = []
    affected_endpoints: list[str] = []


class AffectedAsset(BaseModel):
    host_id: str
    incident_count: int
    # None when this host has no Endpoint row yet (never scored).
    highest_risk: Optional[RiskLevel] = None
    # None when none of this host's incidents had a category (e.g. all
    # manually created) — never inferred.
    dominant_category: Optional[CorrelationPattern] = None


class ThreatAnalyticsResponse(BaseModel):
    window_days: int
    trends: list[CategoryTrend]
    # False when every category's previous_count is 0 — the whole
    # previous window had no detected activity at all (a freshly
    # seeded dataset is the common case), so the frontend can show an
    # explicit "no previous-period data" state instead of a table full
    # of implied 0%/"new" changes.
    has_previous_period_data: bool
    kpis: ThreatAnalyticsKPIs
    daily_trend: list[DailyIncidentCount]
    status_breakdown: list[StatusCount]
    severity_breakdown: list[SeverityCount]
    mitre_techniques: list[MitreTechniqueCount]
    affected_assets: list[AffectedAsset]


async def _category_counts(
    db: AsyncSession, tenant_id: uuid.UUID, start: datetime, end: datetime
) -> dict[CorrelationPattern, int]:
    result = await db.execute(
        select(Incident.category, func.count())
        .where(
            Incident.tenant_id == tenant_id,
            Incident.category.is_not(None),
            Incident.created_at >= start,
            Incident.created_at < end,
        )
        .group_by(Incident.category)
    )
    return {row[0]: row[1] for row in result.all()}


async def _current_window_incidents(db: AsyncSession, tenant_id: uuid.UUID, start: datetime, end: datetime):
    """
    Full row detail for every incident opened in the current window —
    a separate query from _category_counts above (kept independent so
    the existing current-vs-previous category trend, and its tests,
    are untouched) — backs every section below the trend table.
    """
    result = await db.execute(
        select(Incident.id, Incident.status, Incident.category, Incident.alert_ids, Incident.created_at).where(
            Incident.tenant_id == tenant_id, Incident.created_at >= start, Incident.created_at < end
        )
    )
    return result.all()


async def _endpoints_by_host(db: AsyncSession, tenant_id: uuid.UUID, host_ids: list[str]) -> dict[str, Endpoint]:
    if not host_ids:
        return {}
    result = await db.execute(select(Endpoint).where(Endpoint.tenant_id == tenant_id, Endpoint.host_id.in_(host_ids)))
    return {endpoint.host_id: endpoint for endpoint in result.scalars().all()}


def _technique_ids(alert: dict) -> list[str]:
    # Shared with every other incident view via core/mitre_mapping.py —
    # adapters/wazuh.py comma-joins multiple MITRE technique ids into
    # one string ("T1110, T1078"), while the correlation engine and
    # synthetic injector only ever set one.
    return split_technique_ids(alert.get("mitre_technique"))


@dataclass(frozen=True)
class _IncidentSignals:
    """One incident's real, alert-derived signal — computed once per incident, reused by every aggregation below."""

    incident_id: uuid.UUID
    status: IncidentStatus
    category: Optional[CorrelationPattern]
    created_at: datetime
    severity: Optional[Severity]  # None if none of this incident's alert_ids resolved to a real alert document
    hosts: frozenset  # real hosts only — a CloudLens alert's host_id is a cloud resource id, not a host
    users: frozenset  # excludes the "unknown" placeholder user, same as incident_evidence.py
    technique_tactics: dict  # technique_id -> tactic (or None) observed on this incident's own alerts


def _extract_signals(incident, alerts_by_id: dict[str, dict]) -> _IncidentSignals:
    best_severity: Optional[Severity] = None
    hosts: set[str] = set()
    users: set[str] = set()
    technique_tactics: dict[str, Optional[str]] = {}

    for alert_id in incident.alert_ids:
        alert = alerts_by_id.get(alert_id)
        if not alert:
            continue

        try:
            severity = Severity(alert.get("severity"))
        except ValueError:
            severity = None
        if severity is not None and (best_severity is None or _SEVERITY_RANK[severity] > _SEVERITY_RANK[best_severity]):
            best_severity = severity

        host_id = alert.get("host_id")
        if host_id and alert.get("source") != LogSource.CLOUDLENS.value:
            hosts.add(host_id)

        user = alert.get("user")
        if user and user != "unknown":
            users.add(user)

        for technique_id in _technique_ids(alert):
            technique_tactics.setdefault(technique_id, alert.get("mitre_tactic"))

    return _IncidentSignals(
        incident_id=incident.id, status=incident.status, category=incident.category, created_at=incident.created_at,
        severity=best_severity, hosts=frozenset(hosts), users=frozenset(users), technique_tactics=technique_tactics,
    )


def _kpis(signals: list[_IncidentSignals]) -> ThreatAnalyticsKPIs:
    total = len(signals)
    open_count = sum(1 for s in signals if s.status == IncidentStatus.OPEN)
    known_severity = [s for s in signals if s.severity is not None]
    critical_high = sum(1 for s in known_severity if s.severity in (Severity.CRITICAL, Severity.HIGH))
    hosts = {host for s in signals for host in s.hosts}
    users = {user for s in signals for user in s.users}
    categories = {s.category for s in signals if s.category}

    return ThreatAnalyticsKPIs(
        total_incidents=total, open_incidents=open_count, critical_high_incidents=critical_high,
        incidents_with_unknown_severity=total - len(known_severity),
        affected_endpoints=len(hosts), affected_users=len(users), detection_categories=len(categories),
    )


def _status_breakdown(signals: list[_IncidentSignals]) -> list[StatusCount]:
    counts = Counter(s.status for s in signals)
    return [StatusCount(status=status, count=counts.get(status, 0)) for status in IncidentStatus]


def _severity_breakdown(signals: list[_IncidentSignals]) -> list[SeverityCount]:
    counts = Counter(s.severity for s in signals if s.severity is not None)
    order = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
    return [SeverityCount(severity=severity, count=counts.get(severity, 0)) for severity in order]


def _daily_trend(signals: list[_IncidentSignals], start: datetime, end: datetime) -> list[DailyIncidentCount]:
    buckets: dict[str, int] = {}
    day = start
    while day < end:
        buckets[day.strftime("%Y-%m-%d")] = 0
        day += timedelta(days=1)
    for s in signals:
        key = s.created_at.strftime("%Y-%m-%d")
        buckets[key] = buckets.get(key, 0) + 1
    return [DailyIncidentCount(date=date, count=count) for date, count in sorted(buckets.items())]


def _mitre_technique_counts(signals: list[_IncidentSignals]) -> list[MitreTechniqueCount]:
    incident_ids_by_technique: dict[str, set] = {}
    hosts_by_technique: dict[str, set] = {}
    tactic_by_technique: dict[str, Optional[str]] = {}
    for s in signals:
        for technique_id, tactic in s.technique_tactics.items():
            incident_ids_by_technique.setdefault(technique_id, set()).add(s.incident_id)
            hosts_by_technique.setdefault(technique_id, set()).update(s.hosts)
            if tactic and not tactic_by_technique.get(technique_id):
                tactic_by_technique[technique_id] = tactic

    counts = [
        MitreTechniqueCount(
            technique_id=technique_id, tactic=tactic_by_technique.get(technique_id), incident_count=len(incident_ids),
            # Capped so a heavily-recurring technique doesn't balloon the
            # response — the drawer's own count field is still the real
            # total regardless of how many ids/hosts are listed here.
            related_incident_ids=sorted(str(i) for i in incident_ids)[:_MITRE_DETAIL_LIMIT],
            affected_endpoints=sorted(hosts_by_technique.get(technique_id, set()))[:_MITRE_DETAIL_LIMIT],
        )
        for technique_id, incident_ids in incident_ids_by_technique.items()
    ]
    counts.sort(key=lambda c: (-c.incident_count, c.technique_id))
    return counts[:_MITRE_TECHNIQUE_LIMIT]


def _affected_assets(signals: list[_IncidentSignals], endpoints_by_host: dict[str, Endpoint]) -> list[AffectedAsset]:
    incident_ids_by_host: dict[str, set] = {}
    categories_by_host: dict[str, Counter] = {}
    for s in signals:
        for host_id in s.hosts:
            incident_ids_by_host.setdefault(host_id, set()).add(s.incident_id)
            if s.category:
                categories_by_host.setdefault(host_id, Counter())[s.category] += 1

    assets = []
    for host_id, incident_ids in incident_ids_by_host.items():
        endpoint = endpoints_by_host.get(host_id)
        category_counter = categories_by_host.get(host_id)
        dominant_category = category_counter.most_common(1)[0][0] if category_counter else None
        assets.append(AffectedAsset(
            host_id=host_id, incident_count=len(incident_ids),
            highest_risk=endpoint.risk_level if endpoint else None, dominant_category=dominant_category,
        ))
    assets.sort(key=lambda a: (-a.incident_count, a.host_id))
    return assets[:_AFFECTED_ASSET_LIMIT]


async def get_threat_analytics(
    db: AsyncSession, tenant_id: uuid.UUID, window_days: int = _DEFAULT_WINDOW_DAYS
) -> ThreatAnalyticsResponse:
    """Tenant-scoped rollup, newest-count-first, over the given rolling window (default 7 days) vs. the equal-length window immediately before it."""
    now = datetime.now(timezone.utc)
    current_start = now - timedelta(days=window_days)
    previous_start = now - timedelta(days=window_days * 2)

    current_counts = await _category_counts(db, tenant_id, current_start, now)
    previous_counts = await _category_counts(db, tenant_id, previous_start, current_start)

    categories = set(current_counts) | set(previous_counts)
    trends = []
    for category in categories:
        current = current_counts.get(category, 0)
        previous = previous_counts.get(category, 0)
        mitre = get_mitre_technique(category)
        change_pct = None if previous == 0 else round((current - previous) / previous * 100, 1)
        trends.append(
            CategoryTrend(
                category=category,
                mitre_tactic=mitre.tactic,
                mitre_technique_ids=list(mitre.technique_ids),
                current_count=current,
                previous_count=previous,
                change_pct=change_pct,
            )
        )
    trends.sort(key=lambda trend: trend.current_count, reverse=True)
    has_previous_period_data = sum(previous_counts.values()) > 0

    current_incidents = await _current_window_incidents(db, tenant_id, current_start, now)

    all_alert_ids = sorted({alert_id for incident in current_incidents for alert_id in incident.alert_ids})
    alerts = await get_alerts_by_ids(all_alert_ids)
    alerts_by_id = {alert["alert_id"]: alert for alert in alerts if alert.get("alert_id")}

    signals = [_extract_signals(incident, alerts_by_id) for incident in current_incidents]

    all_hosts = sorted({host for s in signals for host in s.hosts})
    endpoints_by_host = await _endpoints_by_host(db, tenant_id, all_hosts)

    return ThreatAnalyticsResponse(
        window_days=window_days,
        trends=trends,
        has_previous_period_data=has_previous_period_data,
        kpis=_kpis(signals),
        daily_trend=_daily_trend(signals, current_start, now),
        status_breakdown=_status_breakdown(signals),
        severity_breakdown=_severity_breakdown(signals),
        mitre_techniques=_mitre_technique_counts(signals),
        affected_assets=_affected_assets(signals, endpoints_by_host),
    )
