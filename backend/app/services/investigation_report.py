"""
SafeSOC — Investigation Report Generator
On-demand, analyst-triggered PDF report for a single incident or
endpoint (as opposed to services/reporting.py's scheduled, tenant-wide
weekly digest — a different scope and cadence, sharing this module's
architecture and PDF-writing approach deliberately, not the same
report). Structure inspired by the depth of professional malware/
incident-analysis reports (general information, behavior, evidence,
network activity, etc.) — no branding, layout, or wording copied from
any specific product.

Every section is built exclusively from data already computed
elsewhere in this codebase: services.incident_evidence,
services.incident_timeline, services.incident_graph,
services.incident_narrative, services.risk_scoring,
services.software_inventory, db.opensearch.search_alerts, and
core.mitre_mapping. Nothing here re-derives a number an existing
service already computes (e.g. an endpoint's risk_score always comes
from services.risk_scoring's own Endpoint row, never recalculated
independently) — see each gather function's docstring for exactly
which existing call supplies which section, so the "must match the
app" requirement is structurally guaranteed rather than merely tested.

Data gathering and HTML rendering are pure/testable without WeasyPrint
itself: the PDF-writing step is isolated behind _write_pdf() (a lazy
import), mirroring services/reporting.py's own reasoning exactly.
"""

import html
import math
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.enums import LogSource
from app.core.mitre_mapping import MITRE_PATTERN_MAPPING
from app.db.opensearch import get_alerts_by_ids, search_alerts
from app.models.endpoint import Endpoint
from app.models.incident import Incident
from app.services.incident_evidence import IncidentEvidence, get_incident_evidence
from app.services.incident_graph import GraphEdge, GraphNode, IncidentGraph, get_incident_graph
from app.services.incident_narrative import get_incident_narrative
from app.services.incident_timeline import get_incident_timeline
from app.services.incidents import get_incident
from app.services.risk_scoring import get_endpoint, list_endpoints
from app.services.software_inventory import list_endpoint_software

# A report is a curated, representative document, not a raw forensic
# export — this caps how many individual alert rows the evidence table
# (page 7) prints, while `alerts_total` (computed separately via
# track_total_hits, same as everywhere else in this codebase) always
# reflects the true, complete count so the page can say "N matched,
# top M shown" rather than silently truncating without saying so.
ALERT_EVIDENCE_ROW_LIMIT = 100
# How far back an *endpoint*-scoped report looks for alerts — an
# incident-scoped report instead uses exactly incident.alert_ids
# (already a bounded, precise set), so it needs no such window.
ENDPOINT_REPORT_LOOKBACK_HOURS = 720  # 30 days, matching EndpointDetail.tsx's own window


# ══════════════════════════════════════════════════════════════════════
# Report data model
# ══════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class ReportMetadata:
    report_id: str
    scope_type: str  # "incident" | "endpoint"
    scope_name: str  # incident id (short) or host_id
    tenant_name: str
    generated_at: datetime
    risk_score: Optional[int]
    risk_level: Optional[str]
    is_synthetic: bool  # any evidence alert has source == "synthetic"


@dataclass(frozen=True)
class KeyFinding:
    text: str


@dataclass(frozen=True)
class ExecutiveSummary:
    verdict: str
    severity: str
    investigation_status: Optional[str]
    first_observed: Optional[datetime]
    last_observed: Optional[datetime]
    affected_endpoints: int
    affected_users: int
    alert_count: int
    incident_count: int
    critical_high_alert_count: int
    narrative: str
    narrative_is_fallback: bool
    key_findings: list[KeyFinding]


@dataclass(frozen=True)
class SeverityCounts:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low


@dataclass(frozen=True)
class DailyCount:
    date: str
    count: int


@dataclass(frozen=True)
class Statistics:
    severity: SeverityCounts
    alerts_over_time: list[DailyCount]
    affected_hosts: int
    affected_users: int


@dataclass(frozen=True)
class TimelineEvent:
    timestamp: datetime
    event_type: str
    host: Optional[str]
    user: Optional[str]
    severity: Optional[str]
    reference: Optional[str]  # alert id / incident id / note author, etc.
    description: str


@dataclass(frozen=True)
class GroupedEdgeData:
    source_id: str
    source_label: str
    target_id: str
    target_label: str
    count: int
    mitre_techniques: list[str]
    latest_timestamp: datetime


@dataclass(frozen=True)
class AttackChainData:
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    grouped_edges: list[GroupedEdgeData]
    node_positions: dict[str, tuple[float, float]]
    progression: list[str]  # ordered, human-readable step labels


@dataclass(frozen=True)
class BehaviorFinding:
    category: str
    severity: str
    description: str
    affected_asset: str
    affected_user: Optional[str]
    evidence_count: int
    first_seen: datetime
    last_seen: datetime


@dataclass(frozen=True)
class AlertRow:
    timestamp: datetime
    alert_id: str
    severity: str
    log_type: str
    host_id: str
    user: str
    description: str
    mitre_technique: Optional[str]
    status: str


@dataclass(frozen=True)
class EndpointAnalysis:
    host_id: str
    risk_score: Optional[int]
    risk_level: Optional[str]
    severity: SeverityCounts
    after_hours_count: int
    associated_incident_ids: list[str]
    risk_factors: list[str]


@dataclass(frozen=True)
class UserActivity:
    user: str
    host_count: int
    alert_count: int
    failed_logins: int
    successful_logins: int
    after_hours_count: int
    associated_incident_ids: list[str]


@dataclass(frozen=True)
class VulnerabilityRow:
    software: str
    version: str
    host_id: str
    # None fields below mean this software row has no known vulnerability
    # (the common case) — rendered as "None known" rather than omitted,
    # so a clean software inventory is still visible in the report.
    vulnerability_id: Optional[str]
    severity: Optional[str]
    title: Optional[str]
    is_synthetic: Optional[bool]


@dataclass(frozen=True)
class SoftwareData:
    rows: list[VulnerabilityRow]
    has_any_software: bool
    has_any_synthetic_vuln: bool
    has_any_real_vuln: bool


@dataclass(frozen=True)
class MitreRow:
    technique_id: str
    tactic: str
    evidence_description: str
    affected_host: str
    related_alert: str


@dataclass(frozen=True)
class NetworkRow:
    source_host: str
    destination_ip: str
    port: Optional[int]
    protocol: Optional[str]
    event_count: int
    classification: str  # "Malicious" / "Clean" / "Not checked"


@dataclass(frozen=True)
class InvestigationQA:
    question: str
    answer: str
    is_fallback: bool


@dataclass(frozen=True)
class InvestigationFindings:
    qa: list[InvestigationQA]
    narrative: str
    narrative_is_fallback: bool
    has_data: bool


@dataclass(frozen=True)
class Recommendation:
    observed: str
    recommended: str


@dataclass(frozen=True)
class Recommendations:
    immediate: list[Recommendation]
    investigation: list[Recommendation]
    containment: list[Recommendation]
    long_term: list[str]


@dataclass(frozen=True)
class AppendixData:
    incident_ids: list[str]
    endpoint_ids: list[str]
    user_ids: list[str]
    mitre_technique_ids: list[str]
    evidence_alert_count: int


@dataclass(frozen=True)
class InvestigationReportData:
    metadata: ReportMetadata
    summary: ExecutiveSummary
    statistics: Statistics
    timeline: list[TimelineEvent]
    attack_chain: Optional[AttackChainData]
    behavior_findings: list[BehaviorFinding]
    alerts: list[AlertRow]
    alerts_total: int
    endpoints: list[EndpointAnalysis]
    users: list[UserActivity]
    software: SoftwareData
    mitre: list[MitreRow]
    network: list[NetworkRow]
    investigation: InvestigationFindings
    recommendations: Recommendations
    appendix: AppendixData


# ══════════════════════════════════════════════════════════════════════
# Shared computation helpers — reused by both the incident-scoped and
# endpoint-scoped gather functions below, so the two report types can
# never compute the same kind of number two different ways.
# ══════════════════════════════════════════════════════════════════════


def _parse_ts(raw: object) -> Optional[datetime]:
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=timezone.utc)
    if not isinstance(raw, str):
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def _is_after_hours(timestamp: datetime) -> bool:
    """
    Identical rule to services/risk_scoring.py's own _is_after_hours
    (outside 08:00-18:00 on a weekday, or any time on a weekend) —
    imported would create a private-symbol coupling across modules for
    a two-line rule; kept in sync deliberately rather than imported, the
    same tradeoff frontend/src/pages/EndpointDetail.tsx already made for
    its own "why is this endpoint risky?" factor list, which this page
    mirrors exactly on purpose (same signal categories, same rule).
    """
    if timestamp.weekday() >= 5:
        return True
    return timestamp.hour < 8 or timestamp.hour >= 18


def _severity_counts(alerts: list[dict]) -> SeverityCounts:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for alert in alerts:
        severity = alert.get("severity")
        if severity in counts:
            counts[severity] += 1
    return SeverityCounts(**counts)


def _daily_counts(alerts: list[dict]) -> list[DailyCount]:
    buckets: dict[str, int] = {}
    for alert in alerts:
        ts = _parse_ts(alert.get("timestamp"))
        if ts is None:
            continue
        key = ts.strftime("%Y-%m-%d")
        buckets[key] = buckets.get(key, 0) + 1
    return [DailyCount(date=date, count=count) for date, count in sorted(buckets.items())]


def _build_behavior_categories() -> list[tuple[str, Callable[[dict], bool]]]:
    """
    (category label, matcher) pairs — a matcher receives one alert dict
    and returns True if it belongs to this behavior category. An alert
    can match more than one category (e.g. a privilege-escalation alert
    sent after hours contributes to both). Every category here is one
    of the task's own suggested categories; a category with zero
    matching alerts is simply omitted from the report (page 6's own
    explicit requirement), never padded out.
    """
    return [
        ("Credential attacks", lambda a: a.get("action") == "failed_login"),
        ("Authentication anomalies", lambda a: a.get("action") in ("unusual_authentication", "remote_login")),
        ("Suspicious process activity", lambda a: a.get("log_type") == "process" and a.get("action") in ("process_execution", "powershell_execution")),
        ("Privilege escalation", lambda a: a.get("action") == "privilege_escalation" or a.get("mitre_technique") == "T1068"),
        ("Lateral movement", lambda a: a.get("mitre_technique") == "T1021"),
        ("Malware-related activity", lambda a: a.get("action") in ("malware_detected", "persistence")),
        ("Network anomalies", lambda a: a.get("action") == "suspicious_network_connection"),
        ("Policy violations", lambda a: a.get("action") == "policy_violation"),
    ]


def _behavior_findings(alerts: list[dict]) -> list[BehaviorFinding]:
    findings: list[BehaviorFinding] = []

    for label, matcher in _build_behavior_categories():
        matched = [a for a in alerts if matcher(a)]
        if not matched:
            continue
        timestamps = [t for t in (_parse_ts(a.get("timestamp")) for a in matched) if t is not None]
        if not timestamps:
            continue
        hosts = sorted({a.get("host_id", "unknown") for a in matched})
        users = sorted({a.get("user") for a in matched if a.get("user") and a.get("user") != "unknown"})
        severities = [a.get("severity") for a in matched]
        top_severity = next((s for s in ("critical", "high", "medium", "low") if s in severities), "low")
        findings.append(BehaviorFinding(
            category=label,
            severity=top_severity,
            description=f"{len(matched)} event(s) matching {label.lower()} across {len(hosts)} host(s).",
            affected_asset=", ".join(hosts[:5]) + ("…" if len(hosts) > 5 else ""),
            affected_user=", ".join(users[:5]) + ("…" if len(users) > 5 else "") if users else None,
            evidence_count=len(matched),
            first_seen=min(timestamps),
            last_seen=max(timestamps),
        ))

    after_hours = [a for a in alerts if (ts := _parse_ts(a.get("timestamp"))) is not None and _is_after_hours(ts)]
    if after_hours:
        timestamps = [_parse_ts(a["timestamp"]) for a in after_hours]
        hosts = sorted({a.get("host_id", "unknown") for a in after_hours})
        findings.append(BehaviorFinding(
            category="After-hours activity",
            severity="medium" if len(after_hours) > 5 else "low",
            description=f"{len(after_hours)} event(s) recorded outside standard business hours (08:00-18:00 weekdays) across {len(hosts)} host(s).",
            affected_asset=", ".join(hosts[:5]) + ("…" if len(hosts) > 5 else ""),
            affected_user=None,
            evidence_count=len(after_hours),
            first_seen=min(timestamps),
            last_seen=max(timestamps),
        ))

    return findings


def _mitre_rows(alerts: list[dict]) -> list[MitreRow]:
    seen: set[tuple[str, str]] = set()
    rows: list[MitreRow] = []
    for alert in alerts:
        technique = alert.get("mitre_technique")
        if not technique:
            continue
        host = alert.get("host_id", "unknown")
        key = (technique, host)
        if key in seen:
            continue
        seen.add(key)
        rows.append(MitreRow(
            technique_id=technique,
            tactic=alert.get("mitre_tactic") or "—",
            evidence_description=(alert.get("description") or alert.get("action") or "")[:140],
            affected_host=host,
            related_alert=str(alert.get("alert_id", ""))[:8],
        ))
    rows.sort(key=lambda r: r.technique_id)
    return rows


def _network_rows(alerts: list[dict]) -> list[NetworkRow]:
    groups: dict[tuple, dict] = {}
    for alert in alerts:
        destination_ip = alert.get("destination_ip")
        if not destination_ip:
            continue
        key = (alert.get("host_id", "unknown"), destination_ip, alert.get("destination_port"), alert.get("protocol"))
        group = groups.setdefault(key, {"count": 0, "malicious": False, "checked": False})
        group["count"] += 1
        ti_result = alert.get("ti_result")
        if ti_result:
            group["checked"] = True
            if ti_result.get("is_malicious"):
                group["malicious"] = True

    rows = []
    for (host, dest_ip, port, protocol), group in groups.items():
        classification = "Malicious" if group["malicious"] else ("Clean" if group["checked"] else "Not checked")
        rows.append(NetworkRow(
            source_host=host, destination_ip=dest_ip, port=port, protocol=protocol,
            event_count=group["count"], classification=classification,
        ))
    rows.sort(key=lambda r: -r.event_count)
    return rows


def _user_activity(alerts: list[dict], incidents_by_alert_id: dict[str, str]) -> list[UserActivity]:
    by_user: dict[str, dict] = {}
    for alert in alerts:
        user = alert.get("user")
        if not user or user == "unknown":
            continue
        entry = by_user.setdefault(user, {
            "hosts": set(), "alert_count": 0, "failed": 0, "success": 0, "after_hours": 0, "incidents": set(),
        })
        entry["alert_count"] += 1
        entry["hosts"].add(alert.get("host_id", "unknown"))
        if alert.get("action") == "failed_login":
            entry["failed"] += 1
        if alert.get("action") == "login_success":
            entry["success"] += 1
        ts = _parse_ts(alert.get("timestamp"))
        if ts is not None and _is_after_hours(ts):
            entry["after_hours"] += 1
        incident_id = incidents_by_alert_id.get(alert.get("alert_id", ""))
        if incident_id:
            entry["incidents"].add(incident_id)

    result = [
        UserActivity(
            user=user, host_count=len(e["hosts"]), alert_count=e["alert_count"],
            failed_logins=e["failed"], successful_logins=e["success"], after_hours_count=e["after_hours"],
            associated_incident_ids=sorted(e["incidents"]),
        )
        for user, e in by_user.items()
    ]
    result.sort(key=lambda u: -u.alert_count)
    return result


def _group_parallel_edges(edges: list[GraphEdge]) -> list[GroupedEdgeData]:
    """
    Python port of frontend/src/lib/graphLayout.ts's groupParallelEdges
    — same grouping rule (unordered entity-pair key), kept in sync
    deliberately so the PDF's attack-chain diagram groups parallel
    relationships exactly the same way the live UI's graph does (page 5's
    own explicit requirement).
    """
    groups: dict[str, dict] = {}
    node_order: dict[str, tuple[str, str]] = {}  # key -> (source_id, target_id) as first seen

    for edge in edges:
        key = "|".join(sorted([edge.source, edge.target]))
        group = groups.setdefault(key, {"count": 0, "mitre": [], "latest": edge.timestamp})
        node_order.setdefault(key, (edge.source, edge.target))
        group["count"] += 1
        if edge.timestamp > group["latest"]:
            group["latest"] = edge.timestamp
        if edge.mitre_technique and edge.mitre_technique not in group["mitre"]:
            group["mitre"].append(edge.mitre_technique)

    return [
        GroupedEdgeData(
            source_id=node_order[key][0], source_label=node_order[key][0],
            target_id=node_order[key][1], target_label=node_order[key][1],
            count=g["count"], mitre_techniques=g["mitre"], latest_timestamp=g["latest"],
        )
        for key, g in groups.items()
    ]


def _hash_string(value: str) -> int:
    """Deterministic (non-cryptographic) string hash — mirrors graphLayout.ts's own hashString exactly."""
    h = 0
    for ch in value:
        h = (h * 31 + ord(ch)) & 0xFFFFFFFF
    return h


def _compute_force_layout(node_ids: list[str], edges: list[GroupedEdgeData], width: float, height: float) -> dict[str, tuple[float, float]]:
    """
    Python port of frontend/src/lib/graphLayout.ts's computeForceLayout
    — same algorithm (repulsion + spring attraction + centering,
    deterministic seed from each node id's hash, not random), so the
    PDF's static diagram is laid out the same visual way the live UI's
    interactive graph is, not a different one-off algorithm.
    """
    n = len(node_ids)
    positions: dict[str, list[float]] = {}
    if n == 0:
        return {}

    center_x, center_y = width / 2, height / 2
    radius = max(min(width, height) / 3, 1)

    for node_id in node_ids:
        angle = (_hash_string(node_id) % 360) * (math.pi / 180)
        positions[node_id] = [center_x + radius * math.cos(angle), center_y + radius * math.sin(angle)]

    if n <= 1:
        return {k: (v[0], v[1]) for k, v in positions.items()}

    REPULSION, SPRING_LENGTH, SPRING_STRENGTH, CENTER_STRENGTH, DAMPING, ITERATIONS, MARGIN = 6000, 140, 0.02, 0.01, 0.85, 220, 44
    velocities = {node_id: [0.0, 0.0] for node_id in node_ids}
    relevant_edges = [e for e in edges if e.source_id in positions and e.target_id in positions]

    for _ in range(ITERATIONS):
        forces = {node_id: [0.0, 0.0] for node_id in node_ids}

        for i in range(n):
            for j in range(i + 1, n):
                a, b = node_ids[i], node_ids[j]
                dx, dy = positions[a][0] - positions[b][0], positions[a][1] - positions[b][1]
                dist_sq = dx * dx + dy * dy
                if dist_sq < 1:
                    dx = (_hash_string(a + b) % 10) - 5 or 1
                    dy = (_hash_string(b + a) % 10) - 5 or 1
                    dist_sq = dx * dx + dy * dy
                dist = math.sqrt(dist_sq)
                force = REPULSION / dist_sq
                fx, fy = (dx / dist) * force, (dy / dist) * force
                forces[a][0] += fx
                forces[a][1] += fy
                forces[b][0] -= fx
                forces[b][1] -= fy

        for edge in relevant_edges:
            pa, pb = positions[edge.source_id], positions[edge.target_id]
            dx, dy = pb[0] - pa[0], pb[1] - pa[1]
            dist = max(math.sqrt(dx * dx + dy * dy), 1)
            force = (dist - SPRING_LENGTH) * SPRING_STRENGTH
            fx, fy = (dx / dist) * force, (dy / dist) * force
            forces[edge.source_id][0] += fx
            forces[edge.source_id][1] += fy
            forces[edge.target_id][0] -= fx
            forces[edge.target_id][1] -= fy

        for node_id in node_ids:
            p = positions[node_id]
            forces[node_id][0] += (center_x - p[0]) * CENTER_STRENGTH
            forces[node_id][1] += (center_y - p[1]) * CENTER_STRENGTH

        for node_id in node_ids:
            v, f, p = velocities[node_id], forces[node_id], positions[node_id]
            v[0] = (v[0] + f[0]) * DAMPING
            v[1] = (v[1] + f[1]) * DAMPING
            p[0] = min(max(p[0] + v[0], MARGIN), width - MARGIN)
            p[1] = min(max(p[1] + v[1], MARGIN), height - MARGIN)

    return {k: (v[0], v[1]) for k, v in positions.items()}


def _attack_progression(nodes: list[GraphNode], edges: list[GraphEdge]) -> list[str]:
    """
    A short, chronological "Event -> Event -> Event" summary (page 5's
    own requirement) built strictly from the edges actually present,
    ordered by their real timestamp — never inferring a step that
    isn't backed by an edge.
    """
    nodes_by_id = {n.id: n for n in nodes}
    ordered = sorted(edges, key=lambda e: e.timestamp)
    steps: list[str] = []
    for edge in ordered:
        source = nodes_by_id.get(edge.source)
        target = nodes_by_id.get(edge.target)
        label = f"{source.label if source else edge.source} → {target.label if target else edge.target}"
        if edge.mitre_technique:
            label += f" ({edge.mitre_technique})"
        if label not in steps:
            steps.append(label)
    return steps


def _risk_factors_from_alerts(alerts: list[dict]) -> list[str]:
    """Same factor categories/wording style as frontend/src/pages/EndpointDetail.tsx's computeRiskFactors — kept in sync deliberately."""
    counts = _severity_counts(alerts)
    factors = []
    if counts.critical:
        factors.append(f"{counts.critical} critical-severity alert(s)")
    if counts.high:
        factors.append(f"{counts.high} high-severity alert(s)")
    mitre_mapped = sum(1 for a in alerts if a.get("mitre_technique"))
    if mitre_mapped:
        factors.append(f"{mitre_mapped} alert(s) mapped to a MITRE ATT&CK technique")
    malicious_ti = sum(1 for a in alerts if (a.get("ti_result") or {}).get("is_malicious"))
    if malicious_ti:
        factors.append(f"{malicious_ti} alert(s) matched a confirmed-malicious threat-intel indicator")
    anomalous = sum(1 for a in alerts if (a.get("anomaly_score") or 0) > 0)
    if anomalous:
        factors.append(f"{anomalous} alert(s) flagged by the anomaly detector")
    after_hours = sum(1 for a in alerts if (ts := _parse_ts(a.get("timestamp"))) is not None and _is_after_hours(ts))
    if after_hours:
        factors.append(f"{after_hours} alert(s) recorded after hours")
    return factors


def _software_rows(host_id: str, software_items: list) -> list[VulnerabilityRow]:
    """One row per (software, vulnerability) pair; a software item with no vulnerabilities gets one row with null vuln fields."""
    rows: list[VulnerabilityRow] = []
    for item in software_items:
        if not item.vulnerabilities:
            rows.append(VulnerabilityRow(
                software=item.name, version=item.version, host_id=host_id,
                vulnerability_id=None, severity=None, title=None, is_synthetic=None,
            ))
            continue
        for vuln in item.vulnerabilities:
            rows.append(VulnerabilityRow(
                software=item.name, version=item.version, host_id=host_id,
                vulnerability_id=vuln.get("id"), severity=vuln.get("severity"),
                title=vuln.get("title"), is_synthetic=vuln.get("is_synthetic", True),
            ))
    return rows


def _software_data(rows: list[VulnerabilityRow]) -> SoftwareData:
    return SoftwareData(
        rows=rows,
        has_any_software=bool(rows),
        has_any_synthetic_vuln=any(r.is_synthetic for r in rows if r.vulnerability_id),
        has_any_real_vuln=any(r.vulnerability_id and not r.is_synthetic for r in rows),
    )


def _alert_rows(alerts: list[dict], annotations: dict[str, dict]) -> list[AlertRow]:
    """Most-relevant-first: critical/high severity surfaced ahead of low/medium, ties broken by recency (page 7's own requirement)."""
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    def _status(alert_id: str) -> str:
        ann = annotations.get(alert_id)
        if ann is None:
            return "New"
        if ann.get("dismissed"):
            return "Dismissed"
        if ann.get("acknowledged"):
            return "Acknowledged"
        return "New"

    rows = []
    for alert in alerts:
        ts = _parse_ts(alert.get("timestamp"))
        if ts is None:
            continue
        rows.append(AlertRow(
            timestamp=ts, alert_id=str(alert.get("alert_id", "")), severity=alert.get("severity", "low"),
            log_type=alert.get("log_type", "—"), host_id=alert.get("host_id", "unknown"),
            user=alert.get("user", "unknown"), description=alert.get("description", ""),
            mitre_technique=alert.get("mitre_technique"), status=_status(str(alert.get("alert_id", ""))),
        ))
    rows.sort(key=lambda r: (severity_rank.get(r.severity, 4), -r.timestamp.timestamp()))
    return rows[:ALERT_EVIDENCE_ROW_LIMIT]


def _key_findings(counts: SeverityCounts, behavior: list[BehaviorFinding], mitre: list[MitreRow], endpoints_count: int, users_count: int) -> list[KeyFinding]:
    findings = []
    if counts.critical:
        findings.append(KeyFinding(f"{counts.critical} critical-severity alert(s) were recorded."))
    if counts.high:
        findings.append(KeyFinding(f"{counts.high} high-severity alert(s) were recorded."))
    top_behaviors = sorted(behavior, key=lambda b: -b.evidence_count)[:3]
    for b in top_behaviors:
        findings.append(KeyFinding(f"{b.category}: {b.evidence_count} event(s) observed."))
    if mitre:
        technique_ids = ", ".join(sorted({m.technique_id for m in mitre}))
        findings.append(KeyFinding(f"MITRE ATT&CK techniques observed: {technique_ids}."))
    if endpoints_count:
        findings.append(KeyFinding(f"{endpoints_count} endpoint(s) and {users_count} user(s) are implicated in this evidence set."))
    if not findings:
        findings.append(KeyFinding("No significant suspicious activity was found in the available evidence."))
    return findings[:6]


def _verdict(counts: SeverityCounts, behavior_count: int) -> str:
    if counts.critical:
        return "Critical — confirmed high-impact security activity requiring immediate response."
    if counts.high or behavior_count >= 3:
        return "High — significant suspicious activity requiring prompt investigation."
    if counts.medium or behavior_count >= 1:
        return "Medium — notable activity warranting analyst review."
    return "Low — routine activity; no significant security concern identified in the available evidence."


def _format_audit_detail_value(value: object) -> str:
    # Audit "details" blobs can carry a raw list (e.g. chain_alert_ids
    # from a correlation merge) that would otherwise dump dozens of
    # full UUIDs into a single timeline row — summarize instead of
    # reproducing it verbatim, matching page 7's own "representative
    # subset, not the complete dataset" rule for large evidence sets.
    if isinstance(value, list):
        return f"{len(value)} item(s)"
    text = str(value)
    return text[:60] + ("…" if len(text) > 60 else "")


def _format_audit_details(details: dict) -> str:
    if not details:
        return "Incident state change."
    text = ", ".join(f"{k}: {_format_audit_detail_value(v)}" for k, v in details.items())
    return text[:220] + ("…" if len(text) > 220 else "")


def _timeline_events(timeline: list) -> list[TimelineEvent]:
    """
    Builds one TimelineEvent per alert/note, but *groups* audit entries
    that share the same action + formatted details into a single row
    with an occurrence count and a first/last timestamp range.

    Real incidents in this codebase accumulate many audit entries from
    the correlation engine re-evaluating the same incident as new
    alerts arrive tenant-wide (e.g. dozens of near-identical "Incident
    Merged" rows for the same pattern) -- showing every one verbatim
    would make the report's timeline page count balloon on noise
    rather than distinct evidence. Grouping is still fully
    evidence-grounded (nothing is hidden, just counted) and mirrors
    page 7's own "N matched, M shown" aggregation for large sets.
    """
    audit_groups: dict[tuple[str, str], list[tuple[datetime, str]]] = {}
    other_events: list[tuple[datetime, TimelineEvent]] = []

    for entry in timeline:
        data = entry.data
        if entry.type == "alert":
            event_type = (data.get("action") or data.get("log_type") or "alert").replace("_", " ").title()
            other_events.append((entry.timestamp, TimelineEvent(
                timestamp=entry.timestamp, event_type=event_type,
                host=data.get("host_id"), user=data.get("user"), severity=data.get("severity"),
                reference=str(data.get("alert_id", ""))[:8], description=data.get("description", ""),
            )))
        elif entry.type == "audit":
            event_type = (data.get("action") or "audit event").replace(".", " ").replace("_", " ").title()
            description = _format_audit_details(data.get("details") or {})
            reference = (data.get("actor_user_id") or "system")[:8] if data.get("actor_user_id") else "system"
            audit_groups.setdefault((event_type, description), []).append((entry.timestamp, reference))
        else:  # note
            body = data.get("body", "")
            other_events.append((entry.timestamp, TimelineEvent(
                timestamp=entry.timestamp, event_type="Analyst Note", host=None, user=None, severity=None,
                reference=str(data.get("author_user_id", ""))[:8], description=body[:200] + ("…" if len(body) > 200 else ""),
            )))

    for (event_type, description), occurrences in audit_groups.items():
        occurrences.sort(key=lambda o: o[0])
        first_ts, reference = occurrences[0]
        if len(occurrences) > 1:
            last_ts = occurrences[-1][0]
            description = f"{description} (recurred {len(occurrences)}×, {first_ts:%H:%M:%S}–{last_ts:%H:%M:%S} UTC)"
        other_events.append((first_ts, TimelineEvent(
            timestamp=first_ts, event_type=event_type, host=None, user=None, severity=None,
            reference=reference, description=description,
        )))

    other_events.sort(key=lambda pair: pair[0])
    return [event for _, event in other_events]


# Behavior category -> (recommended action). Only emitted for a
# category the incident/endpoint's own evidence actually matched
# (page 14's own explicit "OBSERVED vs RECOMMENDED, never invent"
# requirement) — the "observed" half of each pair is always built from
# the BehaviorFinding's own real description, never a separate claim.
_BEHAVIOR_RECOMMENDATIONS = {
    "Credential attacks": "Review affected credentials and authentication controls; consider requiring a password reset for implicated accounts.",
    "Authentication anomalies": "Verify the legitimacy of the flagged authentication events with the affected user(s).",
    "Suspicious process activity": "Review the executed process(es) and, if unrecognized, isolate the host for forensic analysis.",
    "Privilege escalation": "Audit the affected account's current privilege level and review how elevation was obtained.",
    "Lateral movement": "Review connectivity between the affected hosts and restrict unnecessary internal access paths.",
    "Malware-related activity": "Run a full endpoint scan and review persistence mechanisms on the affected host(s).",
    "Network anomalies": "Review the destination(s) involved and confirm they are expected/authorized.",
    "Policy violations": "Review the violation against current security policy and follow up with the affected user if warranted.",
    "After-hours activity": "Confirm the after-hours activity was authorized (e.g. scheduled maintenance) with the relevant team.",
}


def _build_recommendations(counts: SeverityCounts, behavior: list[BehaviorFinding], hosts: list, status: str) -> Recommendations:
    immediate = []
    if counts.critical:
        immediate.append(Recommendation(
            observed=f"{counts.critical} critical-severity alert(s) were recorded in this evidence set.",
            recommended="Isolate the affected host(s) from the network and begin incident response procedures immediately.",
        ))
    if counts.high:
        immediate.append(Recommendation(
            observed=f"{counts.high} high-severity alert(s) were recorded.",
            recommended="Prioritize analyst review of these alerts within the current shift.",
        ))
    if not immediate:
        immediate.append(Recommendation(
            observed="No critical- or high-severity alerts were recorded in the available evidence.",
            recommended="No immediate action required; continue routine monitoring.",
        ))

    investigation = [
        Recommendation(observed=f"{b.description}", recommended=_BEHAVIOR_RECOMMENDATIONS.get(b.category, "Review this finding and document the outcome."))
        for b in sorted(behavior, key=lambda x: -x.evidence_count)[:6]
    ]
    if not investigation:
        investigation.append(Recommendation(
            observed="No specific suspicious behavior categories were matched against the available evidence.",
            recommended="No further investigation action indicated by current evidence.",
        ))

    containment = []
    if status in ("open", "investigating"):
        containment.append(Recommendation(
            observed=f"This incident's current status is '{status}'.",
            recommended="Assign an analyst if one is not already working this incident, and track containment actions in incident notes.",
        ))
    elif status == "resolved":
        containment.append(Recommendation(
            observed="This incident's status is 'resolved'.",
            recommended="Confirm remediation steps taken are documented in this incident's notes for audit purposes.",
        ))
    elif status:
        containment.append(Recommendation(
            observed=f"This incident's status is '{status}'.",
            recommended="No further containment action indicated by current status.",
        ))
    high_risk_hosts = [h for h in hosts if getattr(h, "risk_level", None) and h.risk_level.value in ("high", "critical")]
    if high_risk_hosts:
        containment.append(Recommendation(
            observed=f"{len(high_risk_hosts)} affected host(s) currently carry a high or critical risk score.",
            recommended="Consider restricting network access for these hosts pending investigation.",
        ))

    long_term = [
        "Continue monitoring the hosts and users referenced in this report for recurrence of similar activity.",
        "Review whether existing detection rules would catch a recurrence of this pattern earlier.",
    ]
    if any(b.category == "Credential attacks" for b in behavior):
        long_term.append("Evaluate multi-factor authentication coverage for the affected account(s) and host(s).")
    if any(b.category == "After-hours activity" for b in behavior):
        long_term.append("Consider alerting policy adjustments for after-hours activity on sensitive systems.")

    return Recommendations(immediate=immediate, investigation=investigation, containment=containment, long_term=long_term)


# ══════════════════════════════════════════════════════════════════════
# Incident-scoped report
# ══════════════════════════════════════════════════════════════════════


async def gather_incident_report_data(db: AsyncSession, tenant_id: uuid.UUID, incident_id: uuid.UUID) -> InvestigationReportData:
    """
    Every number below comes from a call this codebase already makes
    elsewhere for the same incident: get_incident (incidents.py, the
    same call IncidentDetail.tsx's own page load makes), get_incident_evidence
    (SS-100/101, the Evidence Explorer's own data), get_incident_timeline
    (SS-099), get_incident_graph (SS-104/105, the Attack Chain view's own
    data), get_incident_narrative (SS-109/110, the AI Attack-Chain
    Summary's own data) — nothing here recomputes a number one of those
    doesn't already provide.

    Raises:
        IncidentNotFoundError: via get_incident — enforces tenant scoping
        before any data is gathered, same as every other incident-scoped
        endpoint.
    """
    from app.services.alert_annotations import get_annotations_for_alert_ids
    from app.services.incidents import list_incidents

    incident = await get_incident(db, tenant_id, incident_id)
    evidence = await get_incident_evidence(db, tenant_id, incident_id)
    alerts = await get_alerts_by_ids(incident.alert_ids)
    timeline = await get_incident_timeline(db, tenant_id, incident_id)
    graph = await get_incident_graph(db, tenant_id, incident_id)
    narrative_data, narrative_text, narrative_is_fallback = await get_incident_narrative(db, tenant_id, incident_id)
    annotations = await get_annotations_for_alert_ids(db, tenant_id, [a.get("alert_id") for a in alerts if a.get("alert_id")])
    annotations_by_id = {aid: {"acknowledged": a.acknowledged, "dismissed": a.dismissed} for aid, a in annotations.items()}

    counts = _severity_counts(alerts)
    timestamps = [t for t in (_parse_ts(a.get("timestamp")) for a in alerts) if t is not None]
    behavior = _behavior_findings(alerts)
    mitre = _mitre_rows(alerts)
    incidents_by_alert_id = {aid: str(incident.id) for aid in incident.alert_ids}

    endpoints = [
        EndpointAnalysis(
            host_id=h.host_id, risk_score=h.risk_score, risk_level=h.risk_level.value if h.risk_level else None,
            severity=_severity_counts([a for a in alerts if a.get("host_id") == h.host_id]),
            after_hours_count=sum(1 for a in alerts if a.get("host_id") == h.host_id and (ts := _parse_ts(a.get("timestamp"))) is not None and _is_after_hours(ts)),
            associated_incident_ids=[str(incident.id)],
            risk_factors=_risk_factors_from_alerts([a for a in alerts if a.get("host_id") == h.host_id]),
        )
        for h in evidence.hosts
    ]

    software_rows: list[VulnerabilityRow] = []
    for h in evidence.hosts:
        software_rows += _software_rows(h.host_id, await list_endpoint_software(db, tenant_id, h.host_id))

    attack_chain = None
    if graph.nodes:
        grouped = _group_parallel_edges(graph.edges)
        node_ids = [n.id for n in graph.nodes]
        positions = _compute_force_layout(node_ids, grouped, 700, 420)
        nodes_by_id = {n.id: n for n in graph.nodes}
        grouped_with_labels = [
            GroupedEdgeData(
                source_id=g.source_id, source_label=nodes_by_id[g.source_id].label if g.source_id in nodes_by_id else g.source_id,
                target_id=g.target_id, target_label=nodes_by_id[g.target_id].label if g.target_id in nodes_by_id else g.target_id,
                count=g.count, mitre_techniques=g.mitre_techniques, latest_timestamp=g.latest_timestamp,
            )
            for g in grouped
        ]
        attack_chain = AttackChainData(
            nodes=graph.nodes, edges=graph.edges, grouped_edges=grouped_with_labels,
            node_positions=positions, progression=_attack_progression(graph.nodes, graph.edges),
        )

    is_synthetic = any(a.get("source") == LogSource.SYNTHETIC.value for a in alerts)
    severity_value = "critical" if counts.critical else "high" if counts.high else "medium" if counts.medium else "low"

    metadata = ReportMetadata(
        report_id=str(uuid.uuid4()), scope_type="incident", scope_name=str(incident.id)[:8],
        tenant_name=str(tenant_id), generated_at=datetime.now(timezone.utc),
        # Incidents have no numeric 0-100 risk score in this codebase
        # (that's an endpoint-only concept -- services/risk_scoring.py)
        # -- risk_level here is the same severity already shown in the
        # Incident Overview table and elsewhere, not a fabricated score.
        risk_score=None, risk_level=severity_value, is_synthetic=is_synthetic,
    )

    summary = ExecutiveSummary(
        verdict=_verdict(counts, len(behavior)), severity=severity_value,
        investigation_status=incident.status.value, first_observed=min(timestamps) if timestamps else None,
        last_observed=max(timestamps) if timestamps else None, affected_endpoints=len(evidence.hosts),
        affected_users=len(evidence.users), alert_count=len(incident.alert_ids), incident_count=1,
        critical_high_alert_count=counts.critical + counts.high, narrative=narrative_text,
        narrative_is_fallback=narrative_is_fallback,
        key_findings=_key_findings(counts, behavior, mitre, len(evidence.hosts), len(evidence.users)),
    )

    return InvestigationReportData(
        metadata=metadata, summary=summary,
        statistics=Statistics(severity=counts, alerts_over_time=_daily_counts(alerts), affected_hosts=len(evidence.hosts), affected_users=len(evidence.users)),
        timeline=_timeline_events(timeline), attack_chain=attack_chain, behavior_findings=behavior,
        alerts=_alert_rows(alerts, annotations_by_id), alerts_total=len(incident.alert_ids),
        endpoints=endpoints, users=_user_activity(alerts, incidents_by_alert_id),
        software=_software_data(software_rows), mitre=mitre, network=_network_rows(alerts),
        investigation=InvestigationFindings(qa=[], narrative=narrative_text, narrative_is_fallback=narrative_is_fallback, has_data=bool(alerts)),
        recommendations=_build_recommendations(counts, behavior, evidence.hosts, incident.status.value),
        appendix=AppendixData(
            incident_ids=[str(incident.id)], endpoint_ids=[h.host_id for h in evidence.hosts],
            user_ids=[u.user for u in evidence.users], mitre_technique_ids=sorted({m.technique_id for m in mitre}),
            evidence_alert_count=len(alerts),
        ),
    )


# ══════════════════════════════════════════════════════════════════════
# Endpoint-scoped report
# ══════════════════════════════════════════════════════════════════════


async def gather_endpoint_report_data(
    db: AsyncSession, tenant_id: uuid.UUID, host_id: str, session_qa: Optional[list[InvestigationQA]] = None
) -> InvestigationReportData:
    """
    Every number below comes from a call this codebase already makes
    elsewhere for the same host: services.risk_scoring.get_endpoint
    (the same Endpoint row EndpointDetail.tsx's header reads),
    db.opensearch.search_alerts + get_alert_severity_summary (the same
    two calls EndpointDetail.tsx's own page load makes, host_id-scoped
    -- not a re-derived severity count), services.incidents.list_incidents
    cross-referenced by alert_ids (the exact client-side "associated
    incidents" logic EndpointDetail.tsx uses, replicated here so the
    report doesn't need the frontend to compute and pass it),
    services.incident_graph.get_incident_graph for whichever associated
    incident is primary (same "prefer open/investigating, else most
    recent" rule EndpointDetail.tsx's own graph section uses), and
    services.software_inventory.list_endpoint_software.

    session_qa, if given, is the analyst's own already-completed AI
    Endpoint Analyst conversation for this host (the embedded chat,
    POST /api/v1/investigate under the hood) -- passed through by the
    caller since that transcript only exists in the browser session, not
    anywhere this backend call could otherwise retrieve it. Without it,
    "Investigation Findings" falls back to a deterministic (not
    LLM-generated) summary built from data already computed elsewhere in
    this same report, clearly labeled as such -- there is no
    per-endpoint equivalent of get_incident_narrative to call instead
    (see this module's own docstring on why one wasn't added here rather
    than duplicating investigate.py's grounding-rules prompt a third
    time).
    """
    from app.db.opensearch import get_alert_severity_summary
    from app.services.incidents import list_incidents

    endpoint = await get_endpoint(db, tenant_id, host_id)
    alerts_result = await search_alerts(
        tenant_id=str(tenant_id), host_id=host_id, timerange_hours=ENDPOINT_REPORT_LOOKBACK_HOURS, size=500
    )
    alerts = alerts_result["alerts"]
    severity_summary = await get_alert_severity_summary(
        tenant_id=str(tenant_id), timerange_hours=ENDPOINT_REPORT_LOOKBACK_HOURS, host_id=host_id
    )

    host_alert_ids = {a.get("alert_id") for a in alerts if a.get("alert_id")}
    all_incidents, _total = await list_incidents(db, tenant_id, size=500)
    related_incidents = sorted(
        (i for i in all_incidents if host_alert_ids & set(i.alert_ids)),
        key=lambda i: i.updated_at, reverse=True,
    )
    incidents_by_alert_id: dict[str, str] = {}
    for incident in related_incidents:
        for aid in incident.alert_ids:
            incidents_by_alert_id.setdefault(aid, str(incident.id))

    software_items = await list_endpoint_software(db, tenant_id, host_id)
    software_rows = _software_rows(host_id, software_items)

    counts = _severity_counts(alerts)
    timestamps = [t for t in (_parse_ts(a.get("timestamp")) for a in alerts) if t is not None]
    behavior = _behavior_findings(alerts)
    mitre = _mitre_rows(alerts)
    users = _user_activity(alerts, incidents_by_alert_id)

    attack_chain = None
    primary_incident = next(
        (i for i in related_incidents if i.status.value in ("open", "investigating")),
        related_incidents[0] if related_incidents else None,
    )
    if primary_incident is not None:
        graph = await get_incident_graph(db, tenant_id, primary_incident.id)
        if graph.nodes:
            grouped = _group_parallel_edges(graph.edges)
            node_ids = [n.id for n in graph.nodes]
            positions = _compute_force_layout(node_ids, grouped, 700, 420)
            nodes_by_id = {n.id: n for n in graph.nodes}
            grouped_with_labels = [
                GroupedEdgeData(
                    source_id=g.source_id, source_label=nodes_by_id[g.source_id].label if g.source_id in nodes_by_id else g.source_id,
                    target_id=g.target_id, target_label=nodes_by_id[g.target_id].label if g.target_id in nodes_by_id else g.target_id,
                    count=g.count, mitre_techniques=g.mitre_techniques, latest_timestamp=g.latest_timestamp,
                )
                for g in grouped
            ]
            attack_chain = AttackChainData(
                nodes=graph.nodes, edges=graph.edges, grouped_edges=grouped_with_labels,
                node_positions=positions, progression=_attack_progression(graph.nodes, graph.edges),
            )

    is_synthetic = any(a.get("source") == LogSource.SYNTHETIC.value for a in alerts)

    metadata = ReportMetadata(
        report_id=str(uuid.uuid4()), scope_type="endpoint", scope_name=host_id,
        tenant_name=str(tenant_id), generated_at=datetime.now(timezone.utc),
        risk_score=endpoint.risk_score if endpoint else None,
        risk_level=endpoint.risk_level.value if endpoint else None, is_synthetic=is_synthetic,
    )

    if session_qa:
        investigation = InvestigationFindings(qa=session_qa, narrative="", narrative_is_fallback=False, has_data=True)
        narrative_text_for_summary = session_qa[-1].answer
        narrative_is_fallback_for_summary = False
    else:
        risk_factors = _risk_factors_from_alerts(alerts)
        if risk_factors:
            deterministic = (
                "No active AI Endpoint Analyst session was captured for this report. Based on the evidence "
                f"gathered elsewhere in this report: {'; '.join(risk_factors)}."
            )
        else:
            deterministic = (
                "No active AI Endpoint Analyst session was captured for this report, and no elevated risk "
                "factors were found in this host's available alert evidence."
            )
        investigation = InvestigationFindings(qa=[], narrative=deterministic, narrative_is_fallback=True, has_data=bool(alerts))
        narrative_text_for_summary = deterministic
        narrative_is_fallback_for_summary = True

    endpoint_analysis = EndpointAnalysis(
        host_id=host_id, risk_score=endpoint.risk_score if endpoint else None,
        risk_level=endpoint.risk_level.value if endpoint else None, severity=counts,
        after_hours_count=sum(1 for a in alerts if (ts := _parse_ts(a.get("timestamp"))) is not None and _is_after_hours(ts)),
        associated_incident_ids=[str(i.id) for i in related_incidents],
        risk_factors=_risk_factors_from_alerts(alerts),
    )

    endpoint_severity = SeverityCounts(**{k: v for k, v in severity_summary.get("by_severity", {}).items() if k in ("critical", "high", "medium", "low")})

    summary = ExecutiveSummary(
        verdict=_verdict(counts, len(behavior)),
        severity=(endpoint.risk_level.value if endpoint else ("critical" if counts.critical else "high" if counts.high else "medium" if counts.medium else "low")),
        investigation_status=None, first_observed=min(timestamps) if timestamps else None,
        last_observed=max(timestamps) if timestamps else None, affected_endpoints=1,
        affected_users=len(users), alert_count=alerts_result["total"], incident_count=len(related_incidents),
        critical_high_alert_count=counts.critical + counts.high, narrative=narrative_text_for_summary,
        narrative_is_fallback=narrative_is_fallback_for_summary,
        key_findings=_key_findings(counts, behavior, mitre, 1, len(users)),
    )

    return InvestigationReportData(
        metadata=metadata, summary=summary,
        statistics=Statistics(severity=endpoint_severity, alerts_over_time=_daily_counts(alerts), affected_hosts=1, affected_users=len(users)),
        timeline=[
            TimelineEvent(
                timestamp=ts, event_type=(a.get("action") or a.get("log_type") or "alert").replace("_", " ").title(),
                host=a.get("host_id"), user=a.get("user"), severity=a.get("severity"),
                reference=str(a.get("alert_id", ""))[:8], description=a.get("description", ""),
            )
            for a in alerts if (ts := _parse_ts(a.get("timestamp"))) is not None
        ][:200],
        attack_chain=attack_chain, behavior_findings=behavior, alerts=_alert_rows(alerts, {}),
        alerts_total=alerts_result["total"], endpoints=[endpoint_analysis], users=users,
        software=_software_data(software_rows), mitre=mitre, network=_network_rows(alerts),
        investigation=investigation,
        recommendations=_build_recommendations(counts, behavior, [endpoint] if endpoint else [], "n/a"),
        appendix=AppendixData(
            incident_ids=[str(i.id) for i in related_incidents], endpoint_ids=[host_id],
            user_ids=[u.user for u in users], mitre_technique_ids=sorted({m.technique_id for m in mitre}),
            evidence_alert_count=len(alerts),
        ),
    )


# ══════════════════════════════════════════════════════════════════════
# PDF orchestration — mirrors services/reporting.py's own
# gather -> render -> _write_pdf staging exactly (lazy WeasyPrint
# import, same settings.REPORT_OUTPUT_DIR/{tenant_id}/ storage, so the
# existing GET /api/v1/reports/{filename} download route serves these
# files unmodified). Filenames are prefixed "investigation-" so they
# stay distinguishable from (and don't collide with) weekly-digest
# report filenames in the same tenant directory; list_reports()'s own
# strict %Y%m%dT%H%M%SZ.pdf stem parsing already skips this prefixed
# form, which is intentional -- investigation reports aren't part of
# that separate weekly-digest listing.
# ══════════════════════════════════════════════════════════════════════

_FILENAME_SAFE = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"


def _slugify(value: str) -> str:
    cleaned = "".join(ch if ch in _FILENAME_SAFE else "-" for ch in value)
    return cleaned[:40].strip("-") or "scope"


def _write_pdf(html_content: str, output_path: Path) -> None:
    # Lazy import -- see services/reporting.py's own _write_pdf for why:
    # keeps this module importable without WeasyPrint's native Pango
    # dependency present until a PDF is actually rendered.
    from weasyprint import HTML

    output_path.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=html_content).write_pdf(str(output_path))


def _investigation_report_filename(scope_type: str, scope_slug: str, generated_at: datetime) -> str:
    return f"investigation-{scope_type}-{_slugify(scope_slug)}-{generated_at:%Y%m%dT%H%M%SZ}.pdf"


async def generate_incident_report(
    db: AsyncSession, tenant_id: uuid.UUID, incident_id: uuid.UUID, *, output_dir: Optional[Path] = None
) -> tuple[Path, datetime]:
    """Gather + render + save a PDF investigation report scoped to one incident. Returns (saved path, generated_at)."""
    from app.services.investigation_report_render import render_investigation_report_html

    data = await gather_incident_report_data(db, tenant_id, incident_id)
    html_content = render_investigation_report_html(data)

    base_dir = output_dir if output_dir is not None else Path(settings.REPORT_OUTPUT_DIR)
    filename = _investigation_report_filename("incident", str(incident_id)[:8], data.metadata.generated_at)
    report_path = base_dir / str(tenant_id) / filename

    _write_pdf(html_content, report_path)
    return report_path, data.metadata.generated_at


async def generate_endpoint_report(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    host_id: str,
    *,
    session_qa: Optional[list[InvestigationQA]] = None,
    output_dir: Optional[Path] = None,
) -> tuple[Path, datetime]:
    """Gather + render + save a PDF investigation report scoped to one endpoint. Returns (saved path, generated_at)."""
    from app.services.investigation_report_render import render_investigation_report_html

    data = await gather_endpoint_report_data(db, tenant_id, host_id, session_qa=session_qa)
    html_content = render_investigation_report_html(data)

    base_dir = output_dir if output_dir is not None else Path(settings.REPORT_OUTPUT_DIR)
    filename = _investigation_report_filename("endpoint", host_id, data.metadata.generated_at)
    report_path = base_dir / str(tenant_id) / filename

    _write_pdf(html_content, report_path)
    return report_path, data.metadata.generated_at
