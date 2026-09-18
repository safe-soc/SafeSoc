"""
SafeSOC — Compliance Center API
GET /api/v1/compliance/requirements — every static requirement (core/
compliance_mapping.py), freshly assessed against the caller's tenant.
GET /api/v1/compliance/requirements/{id} — full detail for one.

Read-only, open to any authenticated role (matches /evidence, /graph,
/narrative, investigation-session GETs) — this Center never writes
anything, and there is no "compliance status" for a client to
manipulate: every value in the response is recomputed server-side on
each request from services/compliance.py, which itself only reads
existing tenant-scoped data. A requirement id (e.g. "DPDP-R2") is not
tenant data — it's the same fixed static list for every tenant — so it
can never be used to reach another tenant's evidence; the evidence
behind it is always computed from current_user.tenant_id, never a
caller-supplied value.
"""

from collections import Counter

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.compliance_mapping import FRAMEWORK_TITLES
from app.core.dependencies import CurrentUser, get_current_user
from app.core.enums import ComplianceFramework, ComplianceStatus
from app.db.postgresql import get_db
from app.models.incident import Incident
from app.schemas.compliance import (
    ComplianceFrameworkSummary,
    ComplianceRequirementDetail,
    ComplianceRequirementSummary,
    CompliancePostureResponse,
    RelatedIncidentRef,
    RelatedInvestigationRef,
)
from app.services import compliance as compliance_service
from app.services.compliance import RequirementAssessment

router = APIRouter(prefix="/api/v1/compliance", tags=["compliance"])


def _requirement_summary(assessment: RequirementAssessment) -> ComplianceRequirementSummary:
    return ComplianceRequirementSummary(
        id=assessment.requirement.id,
        framework=assessment.requirement.framework,
        title=assessment.requirement.title,
        reference=assessment.requirement.reference,
        status=assessment.status,
        evidence_summary=assessment.evidence_summary,
        evidence_count=assessment.evidence_count,
        last_evaluated=assessment.last_evaluated,
    )


def _related_incident_ref(incident: Incident) -> RelatedIncidentRef:
    return RelatedIncidentRef(id=incident.id, status=incident.status, category=incident.category, created_at=incident.created_at)


def _framework_summaries(assessments: list[RequirementAssessment]) -> list[ComplianceFrameworkSummary]:
    summaries = []
    for framework in ComplianceFramework:
        framework_assessments = [a for a in assessments if a.requirement.framework == framework]
        counts = Counter(a.status for a in framework_assessments)
        summaries.append(
            ComplianceFrameworkSummary(
                framework=framework,
                title=FRAMEWORK_TITLES[framework],
                total_requirements=len(framework_assessments),
                evidence_available=counts[ComplianceStatus.EVIDENCE_AVAILABLE],
                partially_supported=counts[ComplianceStatus.PARTIALLY_SUPPORTED],
                gaps=counts[ComplianceStatus.GAP],
                not_assessable=counts[ComplianceStatus.NOT_ASSESSABLE],
            )
        )
    return summaries


@router.get("/requirements", response_model=CompliancePostureResponse)
async def list_requirements(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Compliance posture for the authenticated tenant: KPI totals, a
    per-framework rollup, and the full requirement list — everything
    the /compliance page's KPI row, framework cards, and requirement
    table need in one request. Every status is computed fresh; nothing
    here is a stored snapshot.
    """
    assessments = await compliance_service.get_compliance_posture(db, current_user.tenant_id)
    counts = Counter(a.status for a in assessments)

    return CompliancePostureResponse(
        requirements_assessed=len(assessments),
        evidence_available=counts[ComplianceStatus.EVIDENCE_AVAILABLE],
        partially_supported=counts[ComplianceStatus.PARTIALLY_SUPPORTED],
        gaps=counts[ComplianceStatus.GAP],
        not_assessable=counts[ComplianceStatus.NOT_ASSESSABLE],
        frameworks=_framework_summaries(assessments),
        requirements=[_requirement_summary(a) for a in assessments],
    )


@router.get("/requirements/{requirement_id}", response_model=ComplianceRequirementDetail)
async def get_requirement_detail(
    requirement_id: str,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Full detail for one requirement: the regulatory text, what SafeSOC
    can/cannot observe, current evidence (with related incidents/
    investigations for navigation into the existing investigation
    system), and a recommended next action.

    Raises:
        ComplianceRequirementNotFoundError: (404) if requirement_id doesn't match any static requirement.
    """
    assessment = await compliance_service.get_requirement_detail(db, current_user.tenant_id, requirement_id)

    return ComplianceRequirementDetail(
        id=assessment.requirement.id,
        framework=assessment.requirement.framework,
        title=assessment.requirement.title,
        reference=assessment.requirement.reference,
        authoritative_source=assessment.requirement.authoritative_source,
        requirement_summary=assessment.requirement.requirement_summary,
        what_safesoc_can_observe=assessment.requirement.what_safesoc_can_observe,
        what_safesoc_cannot_verify=assessment.requirement.what_safesoc_cannot_verify,
        recommended_action=assessment.recommended_action,
        status=assessment.status,
        evidence_summary=assessment.evidence_summary,
        evidence_count=assessment.evidence_count,
        metrics=assessment.metrics,
        last_evaluated=assessment.last_evaluated,
        related_incidents=[_related_incident_ref(incident) for incident in assessment.related_incidents],
        related_investigations=[
            RelatedInvestigationRef(session_id=ref.session_id, incident_id=ref.incident_id, created_at=ref.created_at)
            for ref in assessment.related_investigations
        ],
    )
