"""
SafeSOC — Incidents API
POST /api/v1/incidents, GET /api/v1/incidents, GET /api/v1/incidents/{id},
POST /api/v1/incidents/{id}/transitions — incident CRUD and lifecycle
transitions (SS-036). POST /api/v1/incidents/{id}/alerts and
POST|GET /api/v1/incidents/{id}/notes — post-creation alert linking
and investigation notes (SS-037).

Auto-created incidents come from correlation-chain detection (SS-031,
services/incidents.py:create_or_merge_incident); this adds manual
creation plus read/transition access for analysts. Requires a valid
JWT (SS-015); tenant_id is derived from the token, not the caller (SS-016).
"""

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, get_current_user, require_role
from app.core.enums import IncidentStatus, UserRole
from app.db.postgresql import get_db
from app.models.incident import Incident, IncidentNote
from app.schemas.incidents import (
    AlertLinkRequest,
    IncidentAssignRequest,
    IncidentCreateRequest,
    IncidentListResponse,
    IncidentNoteCreateRequest,
    IncidentNoteResponse,
    IncidentResponse,
    IncidentTagsRequest,
    IncidentTimelineResponse,
    IncidentTransitionRequest,
)
from app.schemas.reports import InvestigationReportResponse
from app.services.incident_evidence import IncidentEvidence, get_incident_evidence
from app.services.incident_graph import IncidentGraph, get_incident_graph
from app.services.incident_narrative import IncidentNarrativeResponse, get_incident_narrative
from app.services.incident_summary import IncidentSummary, summarize_incidents
from app.services.incident_timeline import get_incident_timeline
from app.services.incidents import (
    add_note,
    assign_incident,
    create_incident,
    get_incident,
    link_alert,
    link_alerts,
    list_incidents,
    list_notes,
    mark_investigating_on_analyst_action,
    set_tags,
    transition_incident,
)
from app.services.investigation_report import generate_incident_report

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


def _to_response(incident: Incident, summary: IncidentSummary) -> IncidentResponse:
    return IncidentResponse(
        id=incident.id,
        tenant_id=incident.tenant_id,
        status=incident.status,
        alert_ids=incident.alert_ids,
        assigned_analyst_id=incident.assigned_analyst_id,
        category=incident.category,
        confidence=incident.confidence,
        tags=incident.tags,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        hosts=summary.hosts,
        severity=summary.severity,
    )


async def _after_analyst_action(db: AsyncSession, current_user: CurrentUser, incident: Incident) -> Incident:
    """
    An analyst just changed this incident: move it OPEN -> INVESTIGATING
    and return it as it now stands. Route handlers only — see
    services/incidents.py::mark_investigating_on_analyst_action for why
    the service functions themselves (shared with SOAR) never do this.
    """
    if await mark_investigating_on_analyst_action(db, current_user.tenant_id, incident.id, current_user.user_id):
        return await get_incident(db, current_user.tenant_id, incident.id)
    return incident


async def _respond(incident: Incident) -> IncidentResponse:
    """Single-incident response — every endpoint returns hosts/severity, so the UI never sees them blank out."""
    summaries = await summarize_incidents([incident])
    return _to_response(incident, summaries[incident.id])


def _note_to_response(note: IncidentNote) -> IncidentNoteResponse:
    return IncidentNoteResponse(
        id=note.id,
        incident_id=note.incident_id,
        author_user_id=note.author_user_id,
        body=note.body,
        created_at=note.created_at,
    )


@router.post("", response_model=IncidentResponse, status_code=201)
async def create(
    payload: IncidentCreateRequest,
    current_user: CurrentUser = Depends(require_role(UserRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    """Manually open an incident, independent of correlation-chain auto-detection (SS-031)."""
    incident = await create_incident(db, current_user.tenant_id, payload.alert_ids, actor_user_id=current_user.user_id)
    return await _respond(incident)


@router.get("", response_model=IncidentListResponse)
async def list_all(
    status: Optional[IncidentStatus] = Query(None, description="Filter by status"),
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(50, ge=1, le=500, description="Results per page"),
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List incidents scoped to the authenticated tenant, newest first."""
    incidents, total = await list_incidents(db, current_user.tenant_id, status=status, page=page, size=size)
    # One batched alert lookup for the whole page, not one per incident.
    summaries = await summarize_incidents(incidents)
    return IncidentListResponse(
        total=total,
        page=page,
        size=size,
        pages=(total + size - 1) // size if total else 0,
        incidents=[_to_response(incident, summaries[incident.id]) for incident in incidents],
    )


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_one(
    incident_id: uuid.UUID,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Fetch a single incident scoped to the authenticated tenant."""
    incident = await get_incident(db, current_user.tenant_id, incident_id)
    return await _respond(incident)


@router.post("/{incident_id}/transitions", response_model=IncidentResponse)
async def transition(
    incident_id: uuid.UUID,
    payload: IncidentTransitionRequest,
    current_user: CurrentUser = Depends(require_role(UserRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    """
    Move an incident through its lifecycle: open -> investigating ->
    resolved/false_positive. Rejects any other transition (skipping
    ahead, moving backward, or acting on a terminal incident) with 409.
    """
    incident = await transition_incident(
        db, current_user.tenant_id, incident_id, payload.to_status, current_user.user_id
    )
    return await _respond(incident)


@router.post("/{incident_id}/assign", response_model=IncidentResponse)
async def assign(
    incident_id: uuid.UUID,
    payload: IncidentAssignRequest,
    current_user: CurrentUser = Depends(require_role(UserRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    """Assign an incident to an analyst within the authenticated tenant."""
    incident = await assign_incident(
        db, current_user.tenant_id, incident_id, payload.assignee_user_id, actor_user_id=current_user.user_id
    )
    incident = await _after_analyst_action(db, current_user, incident)
    return await _respond(incident)


@router.post("/{incident_id}/tags", response_model=IncidentResponse)
async def set_tags_route(
    incident_id: uuid.UUID,
    payload: IncidentTagsRequest,
    current_user: CurrentUser = Depends(require_role(UserRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    """Replace an incident's free-form tags (SS-106). Audit-logged; visible in the SS-099 timeline."""
    incident = await set_tags(db, current_user.tenant_id, incident_id, payload.tags, actor_user_id=current_user.user_id)
    incident = await _after_analyst_action(db, current_user, incident)
    return await _respond(incident)


@router.post("/{incident_id}/alerts", response_model=IncidentResponse)
async def link_alert_route(
    incident_id: uuid.UUID,
    payload: AlertLinkRequest,
    current_user: CurrentUser = Depends(require_role(UserRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    """
    Link one or more alerts to an incident. Idempotent per alert_id:
    linking one already present is a no-op. SS-108: pass alert_ids
    (a list) to link a batch in one request — a blank entry is
    rejected without blocking the rest (accepted_alert_ids/
    rejected_alert_ids on the response); pass alert_id (singular, the
    original SS-037 shape) for a single link, unchanged.
    """
    if payload.alert_ids is not None:
        incident, accepted, rejected = await link_alerts(
            db, current_user.tenant_id, incident_id, payload.alert_ids, actor_user_id=current_user.user_id
        )
        incident = await _after_analyst_action(db, current_user, incident)
        response = await _respond(incident)
        response.accepted_alert_ids = accepted
        response.rejected_alert_ids = rejected
        return response

    incident = await link_alert(
        db, current_user.tenant_id, incident_id, payload.alert_id, actor_user_id=current_user.user_id
    )
    incident = await _after_analyst_action(db, current_user, incident)
    return await _respond(incident)


@router.post("/{incident_id}/notes", response_model=IncidentNoteResponse, status_code=201)
async def add_note_route(
    incident_id: uuid.UUID,
    payload: IncidentNoteCreateRequest,
    current_user: CurrentUser = Depends(require_role(UserRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    """Append an immutable, timestamped analyst note to an incident."""
    note = await add_note(db, current_user.tenant_id, incident_id, current_user.user_id, payload.body)
    await mark_investigating_on_analyst_action(db, current_user.tenant_id, incident_id, current_user.user_id)
    return _note_to_response(note)


@router.get("/{incident_id}/notes", response_model=list[IncidentNoteResponse])
async def list_notes_route(
    incident_id: uuid.UUID,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List an incident's notes, oldest first."""
    notes = await list_notes(db, current_user.tenant_id, incident_id)
    return [_note_to_response(note) for note in notes]


@router.get("/{incident_id}/timeline", response_model=IncidentTimelineResponse)
async def get_timeline(
    incident_id: uuid.UUID,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Chronological narrative merging linked alerts, audit-log activity, and notes (SS-099)."""
    entries = await get_incident_timeline(db, current_user.tenant_id, incident_id)
    return IncidentTimelineResponse(incident_id=incident_id, entries=entries)


@router.get("/{incident_id}/evidence", response_model=IncidentEvidence)
async def get_evidence(
    incident_id: uuid.UUID,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Distinct entities (hosts/IPs/users/cloud resources) involved in an incident, annotated with risk/TI data (SS-100/101)."""
    return await get_incident_evidence(db, current_user.tenant_id, incident_id)


@router.get("/{incident_id}/graph", response_model=IncidentGraph)
async def get_graph(
    incident_id: uuid.UUID,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Lightweight relationship graph (nodes = SS-100's evidence entities,
    edges = alerts connecting them, MITRE-annotated) — computed fresh
    per request, no graph database (SS-104).
    """
    return await get_incident_graph(db, current_user.tenant_id, incident_id)


@router.post("/{incident_id}/narrative", response_model=IncidentNarrativeResponse)
async def get_narrative(
    incident_id: uuid.UUID,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    AI-generated attack-chain narrative (SS-109/110), grounded only in
    SS-109's aggregated data. Falls back to a deterministic templated
    summary on LLM timeout/failure — never a new failure mode.
    Audit-logged (best-effort, SS-097/098 pattern).
    """
    data, narrative, is_fallback = await get_incident_narrative(
        db, current_user.tenant_id, incident_id, actor_user_id=current_user.user_id
    )
    return IncidentNarrativeResponse(incident_id=incident_id, narrative=narrative, is_fallback=is_fallback, data=data)


@router.post("/{incident_id}/report", response_model=InvestigationReportResponse)
async def generate_report(
    incident_id: uuid.UUID,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Generate a ~10-15 page PDF security investigation report scoped to
    this incident (metadata, timeline, attack chain, MITRE mapping,
    evidence, AI findings, recommendations — see
    services/investigation_report.py). Every figure is drawn from the
    same existing services this incident's own detail page reads, so
    the report can never disagree with what the app already shows.
    Download it via the returned download_url, which is the existing
    GET /api/v1/reports/{filename} route (SS-054) — unmodified.
    """
    path, generated_at = await generate_incident_report(db, current_user.tenant_id, incident_id)
    return InvestigationReportResponse(
        filename=path.name,
        generated_at=generated_at,
        size_bytes=path.stat().st_size,
        download_url=f"/api/v1/reports/{path.name}",
    )
