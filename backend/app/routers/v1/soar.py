"""
SafeSOC — SOAR API
GET /api/v1/soar/playbooks — the static playbook catalog (core/
soar_playbooks.py). GET /api/v1/soar/runs — every playbook run across
the tenant (Phase 3, for the /soar operations page).
GET /api/v1/incidents/{incident_id}/soar/runs[/{run_id}] — one
incident's playbook runs / one run's full detail.
POST /api/v1/incidents/{incident_id}/soar/runs/{run_id}/actions/
{action_id}/approve|reject — the Phase 3 human decision point for an
AWAITING_APPROVAL action.

Every route resolves through an already tenant-verified Incident first
(a run_id or action_id alone can never resolve on its own — see
services/soar.py::get_run/get_action), the same pattern
routers/v1/investigation_sessions.py already establishes. Reads are
open to any authenticated role, matching /evidence, /graph,
/narrative, and the investigation-session GETs; approve/reject require
ANALYST, matching every other write endpoint in this codebase (notes,
tags, investigation-session writes).
"""

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.dependencies import CurrentUser, get_current_user, require_role
from app.core.enums import UserRole
from app.core.soar_playbooks import SOAR_PLAYBOOKS, Playbook
from app.db.postgresql import get_db
from app.models.soar import SoarActionExecution, SoarPlaybookRun
from app.schemas.soar import (
    ApprovalDecisionRequest,
    PlaybookResponse,
    PlaybookStepResponse,
    SoarActionExecutionResponse,
    SoarPlaybookRunDetail,
    SoarPlaybookRunSummary,
)
from app.services import soar as soar_service
from app.workers.soar_worker import execute_soar_action

router = APIRouter(prefix="/api/v1", tags=["soar"])


def _playbook_response(playbook: Playbook) -> PlaybookResponse:
    return PlaybookResponse(
        id=playbook.id,
        title=playbook.title,
        trigger_pattern=playbook.trigger.pattern,
        trigger_min_confidence=playbook.trigger.min_confidence,
        steps=[
            PlaybookStepResponse(
                action_type=step.action_type, parameter_field=step.parameter_field.value, static_parameters=step.static_parameters
            )
            for step in playbook.steps
        ],
    )


def _run_summary(run: SoarPlaybookRun) -> SoarPlaybookRunSummary:
    return SoarPlaybookRunSummary(
        id=run.id, incident_id=run.incident_id, playbook_id=run.playbook_id, triggered_by=run.triggered_by,
        status=run.status, started_at=run.started_at, completed_at=run.completed_at, created_at=run.created_at,
    )


def _action_response(action: SoarActionExecution) -> SoarActionExecutionResponse:
    return SoarActionExecutionResponse(
        id=action.id, action_type=action.action_type, parameters=action.parameters,
        autonomy_class=action.autonomy_class, recommended_by=action.recommended_by, status=action.status,
        approved_by_user_id=action.approved_by_user_id, approved_at=action.approved_at,
        rejected_by_user_id=action.rejected_by_user_id, rejected_at=action.rejected_at,
        decision_reason=action.decision_reason, executed_at=action.executed_at,
        result=action.result, verification_status=action.verification_status, verified_at=action.verified_at,
        created_at=action.created_at,
    )


@router.get("/soar/playbooks", response_model=list[PlaybookResponse])
async def list_playbooks(current_user: CurrentUser = Depends(get_current_user)):
    """The static playbook catalog — the same list for every tenant, not stored in the database."""
    return [_playbook_response(playbook) for playbook in SOAR_PLAYBOOKS]


@router.get("/soar/runs", response_model=list[SoarPlaybookRunDetail])
async def list_all_runs(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Every SOAR playbook run across the tenant's incidents, newest first, with full action detail — for the /soar operations page."""
    runs_with_actions = await soar_service.list_all_runs_with_actions(db, current_user.tenant_id)
    return [
        SoarPlaybookRunDetail(**_run_summary(run).model_dump(), actions=[_action_response(action) for action in actions])
        for run, actions in runs_with_actions
    ]


@router.get("/incidents/{incident_id}/soar/runs", response_model=list[SoarPlaybookRunSummary])
async def list_runs(
    incident_id: uuid.UUID,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """This incident's SOAR playbook runs, newest first."""
    runs = await soar_service.list_runs(db, current_user.tenant_id, incident_id)
    return [_run_summary(run) for run in runs]


@router.get("/incidents/{incident_id}/soar/runs/{run_id}", response_model=SoarPlaybookRunDetail)
async def get_run_detail(
    incident_id: uuid.UUID,
    run_id: uuid.UUID,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Full detail for one playbook run, including every action and its current state."""
    run, actions = await soar_service.get_run(db, current_user.tenant_id, incident_id, run_id)
    return SoarPlaybookRunDetail(**_run_summary(run).model_dump(), actions=[_action_response(action) for action in actions])


@router.post(
    "/incidents/{incident_id}/soar/runs/{run_id}/actions/{action_id}/approve",
    response_model=SoarActionExecutionResponse,
)
async def approve_action(
    incident_id: uuid.UUID,
    run_id: uuid.UUID,
    action_id: uuid.UUID,
    payload: ApprovalDecisionRequest = ApprovalDecisionRequest(),
    current_user: CurrentUser = Depends(require_role(UserRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    """
    Approve an AWAITING_APPROVAL action and queue it for execution via
    the existing Celery SOAR worker (workers/soar_worker.py) — the
    exact same execute_soar_action task Phase 2 already built, never a
    second execution mechanism. The response reflects APPROVED, not a
    fabricated execution outcome: the worker still has to actually run
    it, and callers should re-fetch the run to see the real result.
    """
    action = await soar_service.approve_action(
        db, current_user.tenant_id, incident_id, run_id, action_id, current_user.user_id, payload.reason
    )
    execute_soar_action.delay(str(action.id))
    return _action_response(action)


@router.post(
    "/incidents/{incident_id}/soar/runs/{run_id}/actions/{action_id}/reject",
    response_model=SoarActionExecutionResponse,
)
async def reject_action(
    incident_id: uuid.UUID,
    run_id: uuid.UUID,
    action_id: uuid.UUID,
    payload: ApprovalDecisionRequest = ApprovalDecisionRequest(),
    current_user: CurrentUser = Depends(require_role(UserRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    """Reject an AWAITING_APPROVAL action. Terminal — a rejected action is never queued or executed."""
    action = await soar_service.reject_action(
        db, current_user.tenant_id, incident_id, run_id, action_id, current_user.user_id, payload.reason
    )
    return _action_response(action)
