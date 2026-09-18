"""
SafeSOC — Investigation Sessions API
Persistent, incident-scoped investigation memory (Phase 3):
POST/GET .../investigation/sessions to start/list, GET .../{session_id}
for full state, POST .../ask for a grounded follow-up question, and
POST/PATCH routes for findings/actions/notes. Nested under incidents
(mirrors /evidence, /graph, /narrative) rather than a flat
/api/v1/investigation-sessions/{id} — every route resolves the session
through its incident first (services/investigation_session.py's
get_session), so a session_id can never be used on its own to bypass
incident/tenant authorization. Requires a valid JWT (SS-015);
tenant_id is derived from the token, not the caller (SS-016).

Reads (GET) are open to any authenticated role, matching /evidence,
/graph, /narrative. Writes (ask/notes/findings/actions) require
ANALYST, matching /notes, /tags.
"""

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, get_current_user, require_role
from app.core.enums import UserRole
from app.db.postgresql import get_db
from app.models.investigation_session import InvestigationAction, InvestigationFinding, InvestigationNote, InvestigationSession, InvestigationTurn
from app.schemas.investigation_session import (
    AskQuestionRequest,
    AskQuestionResponse,
    CreateActionRequest,
    CreateFindingRequest,
    CreateNoteRequest,
    EvidenceSummary,
    InvestigationActionResponse,
    InvestigationFindingResponse,
    InvestigationNoteResponse,
    InvestigationSessionDetail,
    InvestigationSessionSummary,
    InvestigationTurnResponse,
    UpdateActionRequest,
    UpdateFindingRequest,
)
from app.services import investigation_session as investigation_session_service

router = APIRouter(prefix="/api/v1/incidents/{incident_id}/investigation", tags=["investigation-sessions"])


def _session_summary(session: InvestigationSession) -> InvestigationSessionSummary:
    return InvestigationSessionSummary(
        id=session.id, incident_id=session.incident_id, created_by_user_id=session.created_by_user_id, created_at=session.created_at
    )


def _turn_response(turn: InvestigationTurn) -> InvestigationTurnResponse:
    return InvestigationTurnResponse(
        id=turn.id, asked_by_user_id=turn.asked_by_user_id, question=turn.question,
        answer=turn.answer, is_fallback=turn.is_fallback, created_at=turn.created_at,
    )


def _finding_response(finding: InvestigationFinding) -> InvestigationFindingResponse:
    return InvestigationFindingResponse(
        id=finding.id, text=finding.text, category=finding.category, origin=finding.origin,
        created_by_user_id=finding.created_by_user_id, confirmed_by_user_id=finding.confirmed_by_user_id,
        confirmed_at=finding.confirmed_at, created_at=finding.created_at, updated_at=finding.updated_at,
    )


def _action_response(action: InvestigationAction) -> InvestigationActionResponse:
    return InvestigationActionResponse(
        id=action.id, description=action.description, status=action.status,
        created_by_user_id=action.created_by_user_id, completed_by_user_id=action.completed_by_user_id,
        completed_at=action.completed_at, created_at=action.created_at,
    )


def _note_response(note: InvestigationNote) -> InvestigationNoteResponse:
    return InvestigationNoteResponse(id=note.id, author_user_id=note.author_user_id, body=note.body, created_at=note.created_at)


@router.post("/sessions", response_model=InvestigationSessionSummary, status_code=201)
async def start_session(
    incident_id: uuid.UUID,
    current_user: CurrentUser = Depends(require_role(UserRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    """Start a fresh investigation session for this incident — never inherits a prior session's findings/turns/notes."""
    session = await investigation_session_service.create_session(db, current_user.tenant_id, incident_id, current_user.user_id)
    return _session_summary(session)


@router.get("/sessions", response_model=list[InvestigationSessionSummary])
async def list_sessions(
    incident_id: uuid.UUID,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """This incident's investigation sessions, newest first — the most recent one is "the current session" to continue."""
    sessions = await investigation_session_service.list_sessions(db, current_user.tenant_id, incident_id)
    return [_session_summary(session) for session in sessions]


@router.get("/sessions/{session_id}", response_model=InvestigationSessionDetail)
async def get_session_detail(
    incident_id: uuid.UUID,
    session_id: uuid.UUID,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Full session state for "View investigation state" — turns, findings, actions, notes, plus freshly-retrieved evidence (never a stored snapshot)."""
    session, evidence_data, turns, findings, actions, notes = await investigation_session_service.get_session_state(
        db, current_user.tenant_id, incident_id, session_id
    )
    return InvestigationSessionDetail(
        id=session.id, incident_id=session.incident_id, created_by_user_id=session.created_by_user_id, created_at=session.created_at,
        evidence=EvidenceSummary(**investigation_session_service.evidence_summary(evidence_data)),
        turns=[_turn_response(turn) for turn in turns],
        findings=[_finding_response(finding) for finding in findings],
        actions=[_action_response(action) for action in actions],
        notes=[_note_response(note) for note in notes],
    )


@router.post("/sessions/{session_id}/ask", response_model=AskQuestionResponse)
async def ask_question(
    incident_id: uuid.UUID,
    session_id: uuid.UUID,
    payload: AskQuestionRequest,
    current_user: CurrentUser = Depends(require_role(UserRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    """
    Ask a grounded follow-up question. The answer is generated from
    live evidence + this session's confirmed findings/hypotheses/open
    questions/recent turns — never from an unconfirmed prior AI answer
    treated as fact. Falls back to a deterministic summary on LLM
    timeout/failure (is_fallback=True), never a failed request.
    """
    turn = await investigation_session_service.ask_question(db, current_user.tenant_id, incident_id, session_id, payload.question, current_user.user_id)
    return AskQuestionResponse(turn=_turn_response(turn))


@router.post("/sessions/{session_id}/findings", response_model=InvestigationFindingResponse, status_code=201)
async def create_finding(
    incident_id: uuid.UUID,
    session_id: uuid.UUID,
    payload: CreateFindingRequest,
    current_user: CurrentUser = Depends(require_role(UserRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    """Record a finding. Always origin=analyst — the AI has no path to create a finding directly, only to answer questions an analyst then judges."""
    finding = await investigation_session_service.create_finding(
        db, current_user.tenant_id, incident_id, session_id, payload.text, payload.category, current_user.user_id
    )
    return _finding_response(finding)


@router.patch("/sessions/{session_id}/findings/{finding_id}", response_model=InvestigationFindingResponse)
async def update_finding(
    incident_id: uuid.UUID,
    session_id: uuid.UUID,
    finding_id: uuid.UUID,
    payload: UpdateFindingRequest,
    current_user: CurrentUser = Depends(require_role(UserRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    """"Mark finding as confirmed" / "Mark finding as hypothesis" — the only place category=confirmed is ever set, always by this explicit analyst action."""
    finding = await investigation_session_service.update_finding_category(
        db, current_user.tenant_id, incident_id, session_id, finding_id, payload.category, current_user.user_id
    )
    return _finding_response(finding)


@router.post("/sessions/{session_id}/actions", response_model=InvestigationActionResponse, status_code=201)
async def create_action(
    incident_id: uuid.UUID,
    session_id: uuid.UUID,
    payload: CreateActionRequest,
    current_user: CurrentUser = Depends(require_role(UserRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    """Record a follow-up action (something to DO) — distinct from a finding's open_question (something not yet KNOWN)."""
    action = await investigation_session_service.create_action(db, current_user.tenant_id, incident_id, session_id, payload.description, current_user.user_id)
    return _action_response(action)


@router.patch("/sessions/{session_id}/actions/{action_id}", response_model=InvestigationActionResponse)
async def update_action(
    incident_id: uuid.UUID,
    session_id: uuid.UUID,
    action_id: uuid.UUID,
    payload: UpdateActionRequest,
    current_user: CurrentUser = Depends(require_role(UserRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    action = await investigation_session_service.update_action_status(
        db, current_user.tenant_id, incident_id, session_id, action_id, payload.status, current_user.user_id
    )
    return _action_response(action)


@router.post("/sessions/{session_id}/notes", response_model=InvestigationNoteResponse, status_code=201)
async def add_note(
    incident_id: uuid.UUID,
    session_id: uuid.UUID,
    payload: CreateNoteRequest,
    current_user: CurrentUser = Depends(require_role(UserRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    """Append a free-form analyst note to this session."""
    note = await investigation_session_service.create_note(db, current_user.tenant_id, incident_id, session_id, payload.body, current_user.user_id)
    return _note_response(note)
