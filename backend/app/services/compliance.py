"""
SafeSOC — Compliance Evidence Assessment
Computes each static ComplianceRequirement's (core/compliance_mapping.py)
evidence status live, tenant-scoped, from existing evidence sources —
services/audit.py (audit trail), services/incidents.py (incident
lifecycle), db/opensearch.py (alerts), and the investigation-session
models (SS-098) — never a stored snapshot, the same "live evidence,
never a cache" principle services/investigation_session.py already
established. No new database table exists for assessments or evidence
(Phase 1 architecture decision, approved before implementation): every
call to this module re-derives the current answer from data that
already exists elsewhere.

IMPORTANT — an EVIDENCE_AVAILABLE or PARTIALLY_SUPPORTED status here
means SafeSOC observed telemetry consistent with the control the
requirement describes. It is NEVER a legal-compliance determination,
and this module must never produce or imply "compliant"/"non-
compliant" language — see core/compliance_mapping.py's own module
docstring and docs/compliance.md for the full reasoning. The
recommended_action text for each requirement acknowledges this
directly ("Requires organizational/legal verification" etc.) rather
than asserting SafeSOC has settled the question.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.compliance_mapping import COMPLIANCE_REQUIREMENTS, ComplianceRequirement, get_requirement
from app.core.config import settings
from app.core.enums import ComplianceStatus, FindingCategory, InvestigationActionStatus
from app.core.exceptions import ComplianceRequirementNotFoundError
from app.db.opensearch import get_alert_severity_summary
from app.models.incident import Incident
from app.models.investigation_session import InvestigationAction, InvestigationFinding, InvestigationSession
from app.models.user import User
from app.services import audit as audit_service
from app.services import incidents as incidents_service

# Lookback window for alert-volume evidence (DPDP-R2) — an evidence
# freshness window, NOT the CERT-In log-retention requirement itself
# (CERTIN-R2 reads the actual configured retention separately, below).
_EVIDENCE_WINDOW_HOURS = 24 * 365
_CERTIN_REQUIRED_RETENTION_DAYS = 180
_RELATED_LIMIT = 5


@dataclass(frozen=True)
class InvestigationRef:
    session_id: uuid.UUID
    incident_id: uuid.UUID
    created_at: datetime


@dataclass
class _LiveEvidence:
    status: ComplianceStatus
    evidence_summary: str
    evidence_count: int
    metrics: dict[str, int]
    related_incidents: list[Incident] = field(default_factory=list)
    related_investigations: list[InvestigationRef] = field(default_factory=list)


@dataclass
class RequirementAssessment:
    requirement: ComplianceRequirement
    status: ComplianceStatus
    evidence_summary: str
    evidence_count: int
    metrics: dict[str, int]
    recommended_action: str
    last_evaluated: datetime
    related_incidents: list[Incident]
    related_investigations: list[InvestigationRef]


async def _recent_incidents(db: AsyncSession, tenant_id: uuid.UUID) -> list[Incident]:
    incidents, _ = await incidents_service.list_incidents(db, tenant_id, page=1, size=_RELATED_LIMIT)
    return incidents


async def _investigation_rollup(db: AsyncSession, tenant_id: uuid.UUID) -> dict:
    """
    Tenant-wide investigation session/finding/action counts. The
    investigation_session tables carry no tenant_id column of their
    own (models/investigation_session.py's own docstring) — tenant
    scoping transits through Incident, same as every other query
    against these tables in this codebase; this just aggregates across
    ALL of a tenant's incidents at once instead of one at a time, a
    genuinely new access pattern the per-incident investigation-
    session service has no reason to expose itself.
    """
    session_count = (
        await db.execute(
            select(func.count(InvestigationSession.id))
            .join(Incident, InvestigationSession.incident_id == Incident.id)
            .where(Incident.tenant_id == tenant_id)
        )
    ).scalar_one()

    confirmed_finding_count = (
        await db.execute(
            select(func.count(InvestigationFinding.id))
            .join(InvestigationSession, InvestigationFinding.session_id == InvestigationSession.id)
            .join(Incident, InvestigationSession.incident_id == Incident.id)
            .where(Incident.tenant_id == tenant_id, InvestigationFinding.category == FindingCategory.CONFIRMED)
        )
    ).scalar_one()

    completed_action_count = (
        await db.execute(
            select(func.count(InvestigationAction.id))
            .join(InvestigationSession, InvestigationAction.session_id == InvestigationSession.id)
            .join(Incident, InvestigationSession.incident_id == Incident.id)
            .where(Incident.tenant_id == tenant_id, InvestigationAction.status == InvestigationActionStatus.COMPLETED)
        )
    ).scalar_one()

    recent_rows = (
        await db.execute(
            select(InvestigationSession.id, InvestigationSession.incident_id, InvestigationSession.created_at)
            .join(Incident, InvestigationSession.incident_id == Incident.id)
            .where(Incident.tenant_id == tenant_id)
            .order_by(InvestigationSession.created_at.desc())
            .limit(_RELATED_LIMIT)
        )
    ).all()

    return {
        "session_count": session_count,
        "confirmed_finding_count": confirmed_finding_count,
        "completed_action_count": completed_action_count,
        "recent": [InvestigationRef(session_id=row[0], incident_id=row[1], created_at=row[2]) for row in recent_rows],
    }


async def _assess_access_control(db: AsyncSession, tenant_id: uuid.UUID) -> _LiveEvidence:
    rows = (
        await db.execute(select(User.role, func.count()).where(User.tenant_id == tenant_id).group_by(User.role))
    ).all()
    role_counts = {role.value: count for role, count in rows}
    total_users = sum(role_counts.values())

    return _LiveEvidence(
        status=ComplianceStatus.EVIDENCE_AVAILABLE,
        evidence_summary=(
            f"{total_users} user(s) under role-based access control (admin/analyst/viewer), enforced via "
            "JWT authentication on every request."
        ),
        evidence_count=total_users,
        metrics={"total_users": total_users, **{f"{role}_users": count for role, count in role_counts.items()}},
    )


async def _assess_log_monitoring(db: AsyncSession, tenant_id: uuid.UUID) -> _LiveEvidence:
    _, audit_total = await audit_service.list_events(db, tenant_id, page=1, size=1)
    _, incident_total = await incidents_service.list_incidents(db, tenant_id, page=1, size=1)
    alert_summary = await get_alert_severity_summary(str(tenant_id), timerange_hours=_EVIDENCE_WINDOW_HOURS)
    alert_total = alert_summary["total"]
    rollup = await _investigation_rollup(db, tenant_id)

    evidence_count = audit_total + incident_total + alert_total + rollup["confirmed_finding_count"] + rollup["completed_action_count"]
    metrics = {
        "audit_events": audit_total,
        "alerts": alert_total,
        "incidents": incident_total,
        "investigation_sessions": rollup["session_count"],
        "confirmed_findings": rollup["confirmed_finding_count"],
        "completed_actions": rollup["completed_action_count"],
    }

    if evidence_count > 0:
        status = ComplianceStatus.EVIDENCE_AVAILABLE
        evidence_summary = (
            f"{audit_total} audit log entries, {alert_total} alerts, and {incident_total} incidents recorded "
            f"for this tenant, with {rollup['confirmed_finding_count']} confirmed investigation findings and "
            f"{rollup['completed_action_count']} completed investigation actions."
        )
    else:
        status = ComplianceStatus.GAP
        evidence_summary = "No audit log entries, alerts, incidents, or investigation activity recorded for this tenant yet."

    return _LiveEvidence(
        status=status,
        evidence_summary=evidence_summary,
        evidence_count=evidence_count,
        metrics=metrics,
        related_incidents=await _recent_incidents(db, tenant_id),
        related_investigations=rollup["recent"],
    )


async def _assess_breach_notification(db: AsyncSession, tenant_id: uuid.UUID) -> _LiveEvidence:
    _, incident_total = await incidents_service.list_incidents(db, tenant_id, page=1, size=1)
    if incident_total > 0:
        evidence_summary = (
            f"{incident_total} incident(s) detected and tracked through their status lifecycle in this tenant, "
            "which can inform a breach-notification decision. SafeSOC does NOT submit notifications to the "
            "Data Protection Board or affected Data Principals."
        )
    else:
        evidence_summary = (
            "No incidents detected in this tenant yet. SafeSOC does NOT submit notifications to the Data "
            "Protection Board or affected Data Principals."
        )

    return _LiveEvidence(
        status=ComplianceStatus.PARTIALLY_SUPPORTED,
        evidence_summary=evidence_summary,
        evidence_count=incident_total,
        metrics={"incidents": incident_total},
        related_incidents=await _recent_incidents(db, tenant_id),
    )


async def _assess_incident_reporting_timeliness(db: AsyncSession, tenant_id: uuid.UUID) -> _LiveEvidence:
    _, incident_total = await incidents_service.list_incidents(db, tenant_id, page=1, size=1)
    if incident_total > 0:
        evidence_summary = (
            f"{incident_total} incident(s) with detection timestamps, severity, and correlation category "
            "available to support a manual CERT-In filing decision. SafeSOC does NOT submit reports to CERT-In."
        )
    else:
        evidence_summary = "No incidents detected in this tenant yet. SafeSOC does NOT submit reports to CERT-In."

    return _LiveEvidence(
        status=ComplianceStatus.PARTIALLY_SUPPORTED,
        evidence_summary=evidence_summary,
        evidence_count=incident_total,
        metrics={"incidents": incident_total},
        related_incidents=await _recent_incidents(db, tenant_id),
    )


async def _assess_log_retention(db: AsyncSession, tenant_id: uuid.UUID) -> _LiveEvidence:
    configured_days = settings.OPENSEARCH_ILM_RETENTION_DAYS
    metrics = {"configured_retention_days": configured_days, "required_retention_days": _CERTIN_REQUIRED_RETENTION_DAYS}

    if configured_days < _CERTIN_REQUIRED_RETENTION_DAYS:
        status = ComplianceStatus.GAP
        evidence_summary = (
            f"Configured alert-log retention is {configured_days} day(s); CERT-In requires at least "
            f"{_CERTIN_REQUIRED_RETENTION_DAYS} days. This does not assess the physical/legal jurisdiction of "
            "the underlying log storage."
        )
    else:
        status = ComplianceStatus.PARTIALLY_SUPPORTED
        evidence_summary = (
            f"Configured alert-log retention is {configured_days} day(s), meeting CERT-In's "
            f"{_CERTIN_REQUIRED_RETENTION_DAYS}-day minimum. This does not assess the physical/legal jurisdiction "
            "of the underlying log storage."
        )

    return _LiveEvidence(status=status, evidence_summary=evidence_summary, evidence_count=configured_days, metrics=metrics)


def _assess_not_assessable(requirement: ComplianceRequirement) -> _LiveEvidence:
    return _LiveEvidence(
        status=ComplianceStatus.NOT_ASSESSABLE,
        evidence_summary="No SafeSOC telemetry applies to this requirement.",
        evidence_count=0,
        metrics={},
    )


def _assess_dpiit_not_applicable(requirement: ComplianceRequirement) -> _LiveEvidence:
    return _LiveEvidence(
        status=ComplianceStatus.NOT_ASSESSABLE,
        evidence_summary=(
            "No directly applicable DPIIT cybersecurity technical control was identified for this assessment. "
            "DPIIT is not being treated as a cybersecurity control framework."
        ),
        evidence_count=0,
        metrics={},
    )


_ASSESSORS: dict[str, Callable] = {
    "access_control": _assess_access_control,
    "log_monitoring": _assess_log_monitoring,
    "breach_notification": _assess_breach_notification,
    "incident_reporting_timeliness": _assess_incident_reporting_timeliness,
    "log_retention": _assess_log_retention,
}


def _recommended_action(requirement: ComplianceRequirement, status: ComplianceStatus) -> str:
    if requirement.id == "DPDP-R1":
        return "No action required from SafeSOC evidence alone — separately verify access control across the wider IT/data environment."
    if requirement.id == "DPDP-R2":
        return (
            "Investigate why no activity has been recorded."
            if status == ComplianceStatus.GAP
            else "Periodically review audit/incident/investigation volume for this tenant to confirm monitoring remains active."
        )
    if requirement.id == "DPDP-R5":
        return "Confirm with your Data Protection Officer / legal team whether any detected incident required notification to the Data Protection Board or affected Data Principals, and that it was sent."
    if requirement.id == "CERTIN-R1":
        return "Confirm with your CERT-In point of contact whether any Annexure I incident was filed within 6 hours of detection."
    if requirement.id == "CERTIN-R2":
        if status == ComplianceStatus.GAP:
            return f"Increase OPENSEARCH_ILM_RETENTION_DAYS to at least {_CERTIN_REQUIRED_RETENTION_DAYS}, and separately verify the hosting jurisdiction of the OpenSearch cluster."
        return "Separately verify the hosting jurisdiction of the OpenSearch cluster — retention duration alone does not establish this."
    return "Requires organizational/legal verification — no SafeSOC action is available for this requirement."


async def _assess(db: AsyncSession, tenant_id: uuid.UUID, requirement: ComplianceRequirement) -> RequirementAssessment:
    if requirement.id == "DPIIT-R1":
        live = _assess_dpiit_not_applicable(requirement)
    elif requirement.evidence_type == "none":
        live = _assess_not_assessable(requirement)
    else:
        live = await _ASSESSORS[requirement.evidence_type](db, tenant_id)

    return RequirementAssessment(
        requirement=requirement,
        status=live.status,
        evidence_summary=live.evidence_summary,
        evidence_count=live.evidence_count,
        metrics=live.metrics,
        recommended_action=_recommended_action(requirement, live.status),
        last_evaluated=datetime.now(timezone.utc),
        related_incidents=live.related_incidents,
        related_investigations=live.related_investigations,
    )


async def get_compliance_posture(db: AsyncSession, tenant_id: uuid.UUID) -> list[RequirementAssessment]:
    """Every static requirement (core/compliance_mapping.py), freshly assessed against this tenant's live evidence."""
    return [await _assess(db, tenant_id, requirement) for requirement in COMPLIANCE_REQUIREMENTS]


async def get_requirement_detail(db: AsyncSession, tenant_id: uuid.UUID, requirement_id: str) -> RequirementAssessment:
    """
    Raises:
        ComplianceRequirementNotFoundError: if requirement_id doesn't match any static requirement.
        Note requirement ids are NOT tenant data — the id space is the same fixed list for every
        tenant; the live evidence behind it is always computed for the caller's own tenant_id
        regardless of what's requested, so a requirement id can never be used to reach another
        tenant's evidence.
    """
    requirement = get_requirement(requirement_id)
    if requirement is None:
        raise ComplianceRequirementNotFoundError(requirement_id)
    return await _assess(db, tenant_id, requirement)
