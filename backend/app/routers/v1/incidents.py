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
    IncidentTransitionRequest,
)
from app.services.incidents import (
    add_note,
    assign_incident,
    create_incident,
    get_incident,
    link_alert,
    list_incidents,
    list_notes,
    transition_incident,
)

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


def _to_response(incident: Incident) -> IncidentResponse:
    return IncidentResponse(
        id=incident.id,
        tenant_id=incident.tenant_id,
        status=incident.status,
        alert_ids=incident.alert_ids,
        assigned_analyst_id=incident.assigned_analyst_id,
        category=incident.category,
        confidence=incident.confidence,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
    )


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
    return _to_response(incident)


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
    return IncidentListResponse(
        total=total,
        page=page,
        size=size,
        pages=(total + size - 1) // size if total else 0,
        incidents=[_to_response(incident) for incident in incidents],
    )


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_one(
    incident_id: uuid.UUID,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Fetch a single incident scoped to the authenticated tenant."""
    incident = await get_incident(db, current_user.tenant_id, incident_id)
    return _to_response(incident)


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
    return _to_response(incident)


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
    return _to_response(incident)


@router.post("/{incident_id}/alerts", response_model=IncidentResponse)
async def link_alert_route(
    incident_id: uuid.UUID,
    payload: AlertLinkRequest,
    current_user: CurrentUser = Depends(require_role(UserRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    """Link an additional alert to an incident. Idempotent: linking the same alert_id twice is a no-op."""
    incident = await link_alert(
        db, current_user.tenant_id, incident_id, payload.alert_id, actor_user_id=current_user.user_id
    )
    return _to_response(incident)


@router.post("/{incident_id}/notes", response_model=IncidentNoteResponse, status_code=201)
async def add_note_route(
    incident_id: uuid.UUID,
    payload: IncidentNoteCreateRequest,
    current_user: CurrentUser = Depends(require_role(UserRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    """Append an immutable, timestamped analyst note to an incident."""
    note = await add_note(db, current_user.tenant_id, incident_id, current_user.user_id, payload.body)
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
