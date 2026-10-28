"""
SafeSOC — Incident Summary
Derives the at-a-glance `hosts` and `severity` fields of an incident
response from its linked alerts, so the Dashboard and Incidents list
can say "Credential brute force · WIN10-FIN-07 · high" instead of a
bare id.

Incident rows store neither (see models/incident.py) — both are read
from the real linked alerts, never guessed. Every incident in a
response is summarized from ONE batched OpenSearch lookup
(db.opensearch.get_alerts_by_ids, the same primitive
threat_analytics.py uses for its window), never one query per incident.

Degrades gracefully: an alert that no longer resolves (e.g. pruned by
ILM retention) is skipped, an incident none of whose alerts resolve
gets hosts=[] and severity=None, and an OpenSearch failure leaves every
incident unsummarized rather than failing the incident listing itself.
"""

import uuid
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

from app.core.enums import CorrelationPattern, LogSource, Severity
from app.core.mitre_mapping import incident_technique_ids
from app.db.opensearch import get_alerts_by_ids
from app.models.incident import Incident
from app.utils.logger import get_logger

logger = get_logger(__name__)

_SEVERITY_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


# Readable names for detected chain patterns, matching the frontend's
# categoryLabel() (frontend/src/lib/format.ts).
_CATEGORY_LABELS: dict[CorrelationPattern, str] = {
    CorrelationPattern.CREDENTIAL_BRUTE_FORCE: "Credential brute force",
    CorrelationPattern.SUCCESSFUL_COMPROMISE: "Successful compromise",
    CorrelationPattern.RECON_TO_EXPLOITATION: "Recon to exploitation",
    CorrelationPattern.PRIVILEGE_ESCALATION: "Privilege escalation",
    CorrelationPattern.DATA_EXFILTRATION: "Data exfiltration",
    CorrelationPattern.LATERAL_MOVEMENT: "Lateral movement",
    CorrelationPattern.RANSOMWARE_PRECURSOR: "Ransomware precursor",
}


def category_label(category: Optional[CorrelationPattern]) -> str:
    """A detected chain's readable name; an incident with no category was opened manually."""
    if category is None:
        return "Manual incident"
    return _CATEGORY_LABELS.get(category, category.value.replace("_", " ").capitalize())


@dataclass(frozen=True)
class IncidentSummary:
    hosts: list[str] = field(default_factory=list)
    severity: Optional[Severity] = None
    # Every MITRE technique the incident maps to: its alerts' own ids
    # plus its category's (core/mitre_mapping.incident_technique_ids).
    mitre_techniques: list[str] = field(default_factory=list)


def summarize_incident(incident: Incident, alerts_by_id: dict[str, dict]) -> IncidentSummary:
    """Hosts by alert count (most first, ties by name) and the highest alert severity."""
    host_counts: Counter[str] = Counter()
    best_severity: Optional[Severity] = None
    alert_techniques: list[Optional[str]] = []

    for alert_id in incident.alert_ids:
        alert = alerts_by_id.get(alert_id)
        if not alert:
            continue
        alert_techniques.append(alert.get("mitre_technique"))

        host_id = alert.get("host_id")
        # A CloudLens alert's host_id is the affected cloud resource id,
        # not a host — same rule as services/incident_evidence.py.
        if host_id and alert.get("source") != LogSource.CLOUDLENS.value:
            host_counts[host_id] += 1

        try:
            severity = Severity(alert.get("severity"))
        except ValueError:
            continue
        if best_severity is None or _SEVERITY_RANK[severity] > _SEVERITY_RANK[best_severity]:
            best_severity = severity

    hosts = sorted(host_counts, key=lambda host: (-host_counts[host], host))
    return IncidentSummary(
        hosts=hosts,
        severity=best_severity,
        mitre_techniques=incident_technique_ids(alert_techniques, incident.category),
    )


async def summarize_incidents(incidents: list[Incident]) -> dict[uuid.UUID, IncidentSummary]:
    """Summarize every incident from a single batched alert lookup."""
    all_alert_ids = sorted({alert_id for incident in incidents for alert_id in incident.alert_ids})
    try:
        alerts = await get_alerts_by_ids(all_alert_ids)
    except Exception as exc:
        logger.warning(
            "Incident summary alert lookup failed",
            incident_count=len(incidents),
            error_type=type(exc).__name__,
            error=str(exc),
        )
        alerts = []
    alerts_by_id = {alert["alert_id"]: alert for alert in alerts if alert.get("alert_id")}
    return {incident.id: summarize_incident(incident, alerts_by_id) for incident in incidents}
