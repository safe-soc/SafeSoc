"""
SafeSOC — SOAR Service
Tenant scoping follows InvestigationSession's own precedent exactly
(see models/soar.py): no tenant_id column on either table. Every query
is reached only through an already tenant-verified Incident row
(services/incidents.py:get_incident) and then filtered by
incident_id/run_id — a run_id alone is never sufficient to reach a
run, the same reasoning investigation_session.py's own docstring gives
for session_id.

Phase 1 (data model, policy, state machine, read paths) is unchanged
by Phase 2's evaluate_triggers() (the correlation-pipeline integration
point) or Phase 3's approve_action()/reject_action() (the human
decision point) below. Actually executing an action
(services/soar_execution.py) and the Celery worker that calls it
(workers/soar_worker.py) remain separate modules — this file only
creates/decides rows and provides pure state-machine guards; it never
itself calls out to Celery or an adapter. The one exception is
_maybe_complete_run, which used to live in soar_execution.py — moved
here in Phase 3 because reject_action (here) needs to call it too, and
having soar_execution.py import it back from here (its existing,
unchanged import direction: soar_execution -> soar, never the other
way) avoids a circular import that duplicating it in both places would
only paper over.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

from pydantic import ValidationError
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    AutonomyClass,
    CorrelationPattern,
    RecommendationSource,
    SoarActionStatus,
    SoarActionType,
    SoarRunStatus,
    SoarTriggerSource,
    SoarVerificationStatus,
)
from app.core.exceptions import (
    InvalidSoarActionTransitionError,
    InvalidSoarRunTransitionError,
    SoarActionExecutionNotFoundError,
    SoarActionParameterError,
    SoarPlaybookNotFoundError,
    SoarPolicyViolationError,
    SoarRunNotFoundError,
)
from app.core.soar_playbooks import (
    get_playbook,
    match_playbook,
    resolve_step_parameters,
    step_evidence_is_available,
)
from app.core.soar_policy import classify
from app.models.incident import Incident
from app.models.soar import SoarActionExecution, SoarPlaybookRun
from app.schemas.soar import ACTION_PARAMETER_MODELS
from app.services.audit import record_event
from app.services.incident_evidence import get_incident_evidence
from app.services.incidents import get_incident
from app.utils.logger import get_logger

logger = get_logger(__name__)


# ── Parameter validation ────────────────────────────────────────────

def validate_action_parameters(action_type: SoarActionType, raw_parameters: dict) -> dict:
    """
    Validate raw_parameters against action_type's closed Pydantic
    model (app/schemas/soar.py::ACTION_PARAMETER_MODELS) — the ONLY
    path parameters may take to reach SoarActionExecution.parameters.
    Never stores a dict that hasn't passed through here first.

    Raises:
        SoarActionParameterError: (422) if raw_parameters doesn't
        satisfy action_type's model — e.g. a missing required field
        (a playbook step whose evidence field resolved to None), or an
        indicator that isn't a valid IP/domain.
    """
    model_cls = ACTION_PARAMETER_MODELS[action_type]
    try:
        validated = model_cls(**raw_parameters)
    except ValidationError as e:
        raise SoarActionParameterError(action_type, str(e)) from e
    return validated.model_dump()


# ── State machine ────────────────────────────────────────────────────
#
# Mirrors services/incidents.py's _ALLOWED_TRANSITIONS/transition_incident
# pattern exactly: a dict of status -> the frozenset of statuses reachable
# from it, guarded by a small function that raises rather than silently
# ignoring an invalid target.

_ALLOWED_RUN_TRANSITIONS: dict[SoarRunStatus, frozenset[SoarRunStatus]] = {
    SoarRunStatus.PENDING: frozenset({SoarRunStatus.RUNNING, SoarRunStatus.AWAITING_APPROVAL, SoarRunStatus.CANCELLED}),
    SoarRunStatus.AWAITING_APPROVAL: frozenset({SoarRunStatus.RUNNING, SoarRunStatus.CANCELLED}),
    SoarRunStatus.RUNNING: frozenset({SoarRunStatus.COMPLETED, SoarRunStatus.FAILED}),
    SoarRunStatus.COMPLETED: frozenset(),
    SoarRunStatus.FAILED: frozenset(),
    SoarRunStatus.CANCELLED: frozenset(),
}

_ALLOWED_ACTION_TRANSITIONS: dict[SoarActionStatus, frozenset[SoarActionStatus]] = {
    SoarActionStatus.PENDING: frozenset({SoarActionStatus.AWAITING_APPROVAL, SoarActionStatus.EXECUTING}),
    SoarActionStatus.AWAITING_APPROVAL: frozenset({SoarActionStatus.APPROVED, SoarActionStatus.REJECTED}),
    SoarActionStatus.APPROVED: frozenset({SoarActionStatus.EXECUTING}),
    SoarActionStatus.REJECTED: frozenset(),
    SoarActionStatus.EXECUTING: frozenset({SoarActionStatus.SUCCEEDED, SoarActionStatus.FAILED}),
    SoarActionStatus.SUCCEEDED: frozenset(),
    # FAILED is terminal in this phase — retry is a deliberately deferred,
    # explicitly-designed future transition, not an oversight (see the
    # Phase 1 task's own instruction not to allow it without one).
    SoarActionStatus.FAILED: frozenset(),
}


def transition_run_status(run: SoarPlaybookRun, to_status: SoarRunStatus) -> None:
    """
    Guard + apply a SoarPlaybookRun status transition in place — pure,
    no I/O; the caller is responsible for committing.

    Raises:
        InvalidSoarRunTransitionError: if to_status isn't reachable
        from run.status.
    """
    if to_status not in _ALLOWED_RUN_TRANSITIONS[run.status]:
        raise InvalidSoarRunTransitionError(run.status, to_status)
    run.status = to_status


def transition_action_status(action: SoarActionExecution, to_status: SoarActionStatus) -> None:
    """
    Guard + apply a SoarActionExecution status transition in place —
    pure, no I/O; the caller is responsible for committing.

    One guard beyond the plain status graph: PENDING -> EXECUTING is
    only reachable when action.autonomy_class is AUTOMATIC (snapshotted
    at creation — see create_playbook_run). An APPROVAL_REQUIRED action
    can only ever reach EXECUTING via PENDING -> AWAITING_APPROVAL ->
    APPROVED -> EXECUTING. This is enforced here, not left to callers'
    discipline, so approval can't be skipped by calling this function
    with a status-graph-valid-looking but policy-violating target.

    Raises:
        InvalidSoarActionTransitionError: if to_status isn't reachable
        from action.status, or if PENDING -> EXECUTING is attempted on
        an action whose autonomy_class isn't AUTOMATIC.
    """
    if to_status not in _ALLOWED_ACTION_TRANSITIONS[action.status]:
        raise InvalidSoarActionTransitionError(action.status, to_status)
    if (
        action.status == SoarActionStatus.PENDING
        and to_status == SoarActionStatus.EXECUTING
        and action.autonomy_class != AutonomyClass.AUTOMATIC
    ):
        raise InvalidSoarActionTransitionError(action.status, to_status)
    action.status = to_status


# Every action status with no further outgoing transitions in
# _ALLOWED_ACTION_TRANSITIONS above — i.e. genuinely done, one way or
# another. PENDING/AWAITING_APPROVAL/APPROVED/EXECUTING are all "still
# has something left to happen" and are deliberately excluded.
_TERMINAL_ACTION_STATUSES = frozenset(
    {SoarActionStatus.SUCCEEDED, SoarActionStatus.FAILED, SoarActionStatus.REJECTED}
)


async def _maybe_complete_run(db: AsyncSession, run: SoarPlaybookRun) -> None:
    """
    Resolve a run once every one of its actions has reached a terminal
    state. Called after an action reaches SUCCEEDED/FAILED
    (services/soar_execution.py::execute_action) or REJECTED
    (reject_action below) — approving an action never itself makes it
    terminal (APPROVED still has to go through EXECUTING), so
    approve_action doesn't need to call this.

    Run-completion semantics (deliberately explicit, and unchanged from
    Phase 2's original RUNNING-only case):

    - RUNNING -> FAILED if any action FAILED, else COMPLETED. A
      REJECTED action does not by itself fail the run: an analyst
      declining one containment step is a deliberate decision, not a
      system failure, and shouldn't overshadow the run's other,
      genuinely-executed actions succeeding.
    - AWAITING_APPROVAL -> CANCELLED. A run only remains
      AWAITING_APPROVAL here if NOTHING in it was ever approved —
      approve_action itself flips an AWAITING_APPROVAL run to RUNNING
      the moment anything is approved (see below), and SUCCEEDED/FAILED
      are only reachable via EXECUTING, which is only reachable via
      APPROVED or an AUTOMATIC PENDING action (impossible here, since a
      run is only ever set to AWAITING_APPROVAL when it has zero
      AUTOMATIC actions — see evaluate_triggers). So reaching this
      branch with every action terminal means every single one was
      REJECTED, and the run genuinely never executed anything.
      CANCELLED — not COMPLETED or FAILED, either of which would
      misrepresent that nothing ran — is the correct outcome. This was
      always a legal transition in _ALLOWED_RUN_TRANSITIONS (Phase 1
      defined AWAITING_APPROVAL -> CANCELLED from the start); Phase 3's
      reject_action is simply the first caller to actually reach it.

    A run in any other state (PENDING, or already terminal) is left
    untouched — this function is idempotent to call defensively.
    """
    if run.status not in (SoarRunStatus.RUNNING, SoarRunStatus.AWAITING_APPROVAL):
        return

    result = await db.execute(select(SoarActionExecution).where(SoarActionExecution.playbook_run_id == run.id))
    actions = list(result.scalars().all())

    if any(action.status not in _TERMINAL_ACTION_STATUSES for action in actions):
        return  # still work in flight

    if run.status == SoarRunStatus.AWAITING_APPROVAL:
        transition_run_status(run, SoarRunStatus.CANCELLED)
    else:
        to_status = (
            SoarRunStatus.FAILED
            if any(action.status == SoarActionStatus.FAILED for action in actions)
            else SoarRunStatus.COMPLETED
        )
        transition_run_status(run, to_status)

    run.completed_at = datetime.now(timezone.utc)
    await db.commit()


# ── Creation ─────────────────────────────────────────────────────────

# Why a playbook step produced no action, recorded verbatim in the
# soar.action.skipped audit event's `reason`. Two genuinely different
# situations that must never be collapsed into one: the first is
# incomplete telemetry (nothing was wrong, there was simply nothing to
# act on), the second is a value that failed validation and was
# therefore refused. Both are recorded; only the second is a fail-closed
# refusal. See create_playbook_run.
_SKIP_EVIDENCE_UNAVAILABLE = "required_evidence_unavailable"
_SKIP_PARAMETERS_INVALID = "parameter_validation_failed"

async def _record_audit_event(
    db: AsyncSession, tenant_id: uuid.UUID, action: str, run_id: uuid.UUID, details: Optional[dict] = None
) -> None:
    """Best-effort audit logging — same tolerance/reasoning as services/incidents.py's own _record_audit_event."""
    try:
        await record_event(
            db, tenant_id, action=action, target_type="soar_playbook_run", target_id=str(run_id), details=details or {}
        )
    except Exception as e:
        logger.warning(
            "Audit logging failed for SOAR playbook run", action=action, run_id=str(run_id),
            error_type=type(e).__name__, error=str(e),
        )


async def create_playbook_run(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
    playbook_id: str,
    triggered_by: SoarTriggerSource = SoarTriggerSource.MANUAL,
) -> SoarPlaybookRun:
    """
    Instantiate a playbook run against an incident: validates the
    incident belongs to this tenant, looks up the static playbook
    (core/soar_playbooks.py), resolves each step's parameters against
    the incident's live evidence (services/incident_evidence.py —
    REUSED, not duplicated), validates those parameters per-action-type
    (validate_action_parameters above), and creates one
    SoarActionExecution row per step with autonomy_class snapshotted
    from core/soar_policy.py::classify() at this moment.

    Every created action starts at status=PENDING; advancing it further
    is evaluate_triggers'/soar_execution's job, not this function's.

    A step is SKIPPED — no action row created for it, the rest of the
    playbook unaffected — in exactly two cases, each recorded as its
    own audit event (see _SKIP_* below) so the omission is never
    silent:

    - The incident doesn't carry the evidence the step needs
      (step_evidence_is_available, e.g. a PRIMARY_IP step on an
      incident whose alerts never captured a source/destination IP).
      Incomplete telemetry is an expected operating condition, not an
      error: SafeSOC responds with what it can actually act on rather
      than refusing to respond at all.
    - The step's parameters ARE resolvable but fail validation
      (validate_action_parameters — e.g. an indicator that isn't a
      valid IP/domain, or one carrying a disallowed character). This
      stays fail-closed: no action row is created, so nothing can ever
      execute with a parameter that didn't pass validation. It is
      contained to the offending step instead of destroying the run.

    Neither case fabricates an action row in a pretend-executed state:
    a skipped step has no SoarActionExecution at all, and the audit
    trail (surfaced on the incident timeline) is what records that it
    was considered and why it couldn't run.

    Raises:
        IncidentNotFoundError: via get_incident — also enforces tenant
        ownership before anything else happens.
        SoarPlaybookNotFoundError: if playbook_id isn't a known static playbook.
    """
    incident = await get_incident(db, tenant_id, incident_id)

    playbook = get_playbook(playbook_id)
    if playbook is None:
        raise SoarPlaybookNotFoundError(playbook_id)

    evidence = await get_incident_evidence(db, tenant_id, incident.id)
    evidence_fields = {
        "hosts": [host.host_id for host in evidence.hosts],
        "ips": [ip.ip for ip in evidence.ips],
        "users": [user.user for user in evidence.users],
    }

    # Resolve + validate every step BEFORE creating anything, so a
    # skipped step can never leave a half-built action behind.
    prepared_actions: list[tuple[SoarActionType, dict, AutonomyClass]] = []
    skipped_steps: list[tuple[SoarActionType, str, str]] = []  # (action_type, reason, detail)
    for step in playbook.steps:
        if not step_evidence_is_available(step, evidence_fields):
            skipped_steps.append((step.action_type, _SKIP_EVIDENCE_UNAVAILABLE, step.parameter_field.value))
            continue
        raw_parameters = resolve_step_parameters(step, evidence_fields)
        try:
            validated_parameters = validate_action_parameters(step.action_type, raw_parameters)
        except SoarActionParameterError as e:
            skipped_steps.append((step.action_type, _SKIP_PARAMETERS_INVALID, str(e)))
            continue
        prepared_actions.append((step.action_type, validated_parameters, classify(step.action_type)))

    run = SoarPlaybookRun(
        incident_id=incident.id, playbook_id=playbook.id, triggered_by=triggered_by, status=SoarRunStatus.PENDING
    )
    db.add(run)
    await db.flush()  # assign run.id without committing yet

    for action_type, validated_parameters, autonomy_class in prepared_actions:
        db.add(SoarActionExecution(
            playbook_run_id=run.id,
            action_type=action_type,
            parameters=validated_parameters,
            autonomy_class=autonomy_class,
            recommended_by=RecommendationSource.PLAYBOOK_AUTO,
            status=SoarActionStatus.PENDING,
            verification_status=SoarVerificationStatus.NOT_VERIFIED,
        ))

    await db.commit()
    await db.refresh(run)
    await _record_audit_event(
        db, tenant_id, "soar.playbook_run.created", run.id,
        details={"playbook_id": playbook.id, "incident_id": str(incident.id), "triggered_by": triggered_by.value},
    )
    for action_type, reason, detail in skipped_steps:
        logger.info(
            "SOAR playbook step skipped", playbook_id=playbook.id, run_id=str(run.id),
            incident_id=str(incident.id), action_type=action_type.value, reason=reason,
        )
        await _record_audit_event(
            db, tenant_id, "soar.action.skipped", run.id,
            details={
                "action_type": action_type.value,
                "incident_id": str(incident.id),
                "playbook_id": playbook.id,
                "reason": reason,
                "detail": detail,
            },
        )
    return run


# ── Reads (tenant-scoped through Incident, mirrors investigation_session.py) ──

async def list_runs(db: AsyncSession, tenant_id: uuid.UUID, incident_id: uuid.UUID) -> list[SoarPlaybookRun]:
    """This incident's playbook runs, newest first.

    Raises:
        IncidentNotFoundError: via get_incident.
    """
    incident = await get_incident(db, tenant_id, incident_id)
    result = await db.execute(
        select(SoarPlaybookRun).where(SoarPlaybookRun.incident_id == incident.id).order_by(SoarPlaybookRun.created_at.desc())
    )
    return list(result.scalars().all())


async def get_run(
    db: AsyncSession, tenant_id: uuid.UUID, incident_id: uuid.UUID, run_id: uuid.UUID
) -> tuple[SoarPlaybookRun, list[SoarActionExecution]]:
    """
    One playbook run plus its actions, scoped to a (tenant-verified)
    incident.

    Raises:
        IncidentNotFoundError: via get_incident.
        SoarRunNotFoundError: if run_id doesn't exist, or exists but
        belongs to a different incident (same tenant or not) — a
        run_id alone is never sufficient to reach a run.
    """
    incident = await get_incident(db, tenant_id, incident_id)

    result = await db.execute(
        select(SoarPlaybookRun).where(SoarPlaybookRun.id == run_id, SoarPlaybookRun.incident_id == incident.id)
    )
    run = result.scalar_one_or_none()
    if run is None:
        raise SoarRunNotFoundError(run_id)

    actions_result = await db.execute(
        select(SoarActionExecution).where(SoarActionExecution.playbook_run_id == run.id).order_by(SoarActionExecution.created_at)
    )
    return run, list(actions_result.scalars().all())


# ── Trigger evaluation (Phase 2) ─────────────────────────────────────

async def evaluate_triggers(
    db: AsyncSession, tenant_id: uuid.UUID, incident_id: uuid.UUID, pattern: CorrelationPattern, confidence: float,
) -> Optional[tuple[SoarPlaybookRun, list[uuid.UUID]]]:
    """
    Match a just-detected correlation pattern (services/correlation.py,
    UNCHANGED) against the static playbook catalog
    (core/soar_playbooks.py::match_playbook) and, on a match, create a
    SoarPlaybookRun via create_playbook_run above.

    Deterministically idempotent per (incident, playbook): the same
    incident re-evaluated for the same matching playbook — e.g. the
    same evolving attack chain re-detected as more alerts join it,
    which create_or_merge_incident already treats as a merge into the
    same incident rather than a new one — creates at most one run. A
    Postgres advisory lock keyed on (incident_id, playbook_id) mirrors
    create_or_merge_incident's own technique for exactly this class of
    problem: two concurrent evaluations for the same incident can't
    both pass the "does a run already exist" check before either has
    committed.

    This function is intentionally Celery-agnostic — it only creates
    rows and returns which of them are ready to execute; the caller
    (workers/correlation_worker.py) is responsible for actually queuing
    them via workers/soar_worker.py, keeping this service layer free of
    a reverse dependency on the worker package.

    Incomplete telemetry never fails this call: create_playbook_run
    skips (and audits) any step whose evidence the incident doesn't
    carry, so a match against a partially-observed incident produces a
    run holding whatever WAS actionable. If that leaves no actions at
    all, the run is cancelled immediately rather than left waiting on
    an approval that can never arrive.

    Returns:
        None if no playbook's trigger matches this pattern/confidence,
        or if a run for the matching playbook already exists for this
        incident. Otherwise (run, automatic_action_ids) — the ids of
        the just-created actions the caller should queue for execution
        (only ever the AUTOMATIC ones). Every APPROVAL_REQUIRED action
        is transitioned PENDING -> AWAITING_APPROVAL immediately (via
        services/soar.py's own Phase 1 state-machine guard, unchanged)
        so it's visibly waiting on an analyst the moment a run is
        created — never included in the returned ids, so nothing
        queues one for execution in Phase 2 either way; see
        services/soar_execution.py's own docstring on why AUTOMATIC-
        only execution is the hard safety backstop, not just this
        omission.
    """
    matched = match_playbook(pattern, confidence)
    if matched is None:
        return None

    await db.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:lock_key))"), {"lock_key": f"soar_trigger:{incident_id}:{matched.id}"}
    )

    existing_result = await db.execute(
        select(SoarPlaybookRun).where(SoarPlaybookRun.incident_id == incident_id, SoarPlaybookRun.playbook_id == matched.id)
    )
    if existing_result.scalar_one_or_none() is not None:
        return None  # already triggered for this incident — no duplicate run

    run = await create_playbook_run(db, tenant_id, incident_id, matched.id, triggered_by=SoarTriggerSource.AUTO_TRIGGER)
    await _record_audit_event(
        db, tenant_id, "soar.playbook.triggered", run.id,
        details={"playbook_id": matched.id, "pattern": pattern.value, "confidence": round(confidence, 2)},
    )

    actions_result = await db.execute(select(SoarActionExecution).where(SoarActionExecution.playbook_run_id == run.id))
    actions = list(actions_result.scalars().all())

    if not actions:
        # Every step was skipped (see create_playbook_run) — there is
        # nothing to run and nothing to approve. Settling the run
        # immediately is the honest outcome: leaving it PENDING, or
        # sending it to AWAITING_APPROVAL as the branch below would,
        # produces a run that waits forever on an approval that can
        # never come. PENDING -> CANCELLED is already legal in
        # _ALLOWED_RUN_TRANSITIONS; no new status is needed to say this.
        transition_run_status(run, SoarRunStatus.CANCELLED)
        run.completed_at = datetime.now(timezone.utc)
        await db.commit()
        await _record_audit_event(
            db, tenant_id, "soar.playbook_run.cancelled", run.id,
            details={
                "playbook_id": matched.id,
                "incident_id": str(incident_id),
                "reason": "no_actions_instantiable",
            },
        )
        logger.info(
            "SOAR playbook matched but produced no actions", playbook_id=matched.id,
            incident_id=str(incident_id), run_id=str(run.id),
        )
        return run, []

    automatic_actions = [action for action in actions if action.autonomy_class == AutonomyClass.AUTOMATIC]
    approval_required_actions = [action for action in actions if action.autonomy_class == AutonomyClass.APPROVAL_REQUIRED]

    for action in approval_required_actions:
        transition_action_status(action, SoarActionStatus.AWAITING_APPROVAL)

    transition_run_status(run, SoarRunStatus.RUNNING if automatic_actions else SoarRunStatus.AWAITING_APPROVAL)
    run.started_at = datetime.now(timezone.utc)
    await db.commit()

    for action in approval_required_actions:
        await _record_audit_event(
            db, tenant_id, "soar.action.awaiting_approval", run.id, details={"action_id": str(action.id), "action_type": action.action_type.value}
        )
    for action in automatic_actions:
        await _record_audit_event(
            db, tenant_id, "soar.action.queued", run.id, details={"action_id": str(action.id), "action_type": action.action_type.value}
        )

    return run, [action.id for action in automatic_actions]


# ── Human approval workflow (Phase 3) ────────────────────────────────

async def get_action(
    db: AsyncSession, tenant_id: uuid.UUID, incident_id: uuid.UUID, run_id: uuid.UUID, action_id: uuid.UUID
) -> tuple[SoarPlaybookRun, SoarActionExecution]:
    """
    Resolve one action, scoped through an already tenant-verified
    incident AND its run — never a bare action_id lookup. Reuses
    get_run's own incident/run scoping exactly, then filters within
    that run's own action list (drawn from the same query get_run
    already ran), so "this action belongs to this run" is true by
    construction rather than a separate check that could drift.

    Raises:
        IncidentNotFoundError: via get_run -> get_incident.
        SoarRunNotFoundError: via get_run — run_id doesn't exist, or
        belongs to a different incident.
        SoarActionExecutionNotFoundError: action_id doesn't exist, or
        belongs to a different run (same incident or not).
    """
    run, actions = await get_run(db, tenant_id, incident_id, run_id)
    action = next((a for a in actions if a.id == action_id), None)
    if action is None:
        raise SoarActionExecutionNotFoundError(action_id)
    return run, action


async def approve_action(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
    run_id: uuid.UUID,
    action_id: uuid.UUID,
    approved_by_user_id: uuid.UUID,
    reason: Optional[str] = None,
) -> SoarActionExecution:
    """
    Approve an AWAITING_APPROVAL action. Sets it to APPROVED — the
    Celery worker (workers/soar_worker.py) still has to actually run
    it; the caller (routers/v1/soar.py) queues that via the exact same
    execute_soar_action task Phase 2 already built, never a second
    execution mechanism. services/soar_execution.py::execute_action
    independently re-verifies this action_type is still classified
    APPROVAL_REQUIRED before running it — the check here is a second,
    earlier layer, not the only one.

    If this run was still AWAITING_APPROVAL (i.e. had zero AUTOMATIC
    actions of its own), approving flips it to RUNNING — the same,
    already-legal AWAITING_APPROVAL -> RUNNING transition Phase 1
    defined; this is simply its first real caller.

    Idempotent: approving an action that's already APPROVED returns it
    unchanged rather than raising.

    Raises:
        IncidentNotFoundError / SoarRunNotFoundError /
        SoarActionExecutionNotFoundError: via get_action.
        InvalidSoarActionTransitionError: action.status is neither
        AWAITING_APPROVAL nor (idempotently) already APPROVED — e.g.
        it was already REJECTED, or hasn't reached AWAITING_APPROVAL
        at all yet.
        SoarPolicyViolationError: action_type is not classified
        APPROVAL_REQUIRED right now (a policy change since it was
        queued) — refuses to approve something that either shouldn't
        need approval anymore or was never meant to run at all.
    """
    run, action = await get_action(db, tenant_id, incident_id, run_id, action_id)

    if action.status == SoarActionStatus.APPROVED:
        return action  # idempotent no-op — a duplicate approval request

    if action.status != SoarActionStatus.AWAITING_APPROVAL:
        raise InvalidSoarActionTransitionError(action.status, SoarActionStatus.APPROVED)

    autonomy_class = classify(action.action_type)
    if autonomy_class != AutonomyClass.APPROVAL_REQUIRED:
        raise SoarPolicyViolationError(action.action_type, autonomy_class)

    transition_action_status(action, SoarActionStatus.APPROVED)
    action.approved_by_user_id = approved_by_user_id
    action.approved_at = datetime.now(timezone.utc)
    action.decision_reason = reason

    if run.status == SoarRunStatus.AWAITING_APPROVAL:
        transition_run_status(run, SoarRunStatus.RUNNING)

    await db.commit()
    await _record_audit_event(
        db, tenant_id, "soar.action.approved", run.id,
        details={
            "action_id": str(action.id),
            "action_type": action.action_type.value,
            "incident_id": str(incident_id),
            "run_id": str(run.id),
            "autonomy_class": autonomy_class.value,
            "approved_by_user_id": str(approved_by_user_id),
            "reason": reason,
        },
    )
    return action


async def reject_action(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
    run_id: uuid.UUID,
    action_id: uuid.UUID,
    rejected_by_user_id: uuid.UUID,
    reason: Optional[str] = None,
) -> SoarActionExecution:
    """
    Reject an AWAITING_APPROVAL action. Sets it to REJECTED — terminal;
    _ALLOWED_ACTION_TRANSITIONS has no outgoing transition from
    REJECTED, so a rejected action can never subsequently execute,
    structurally, not just by convention. Never queues anything.

    Calls _maybe_complete_run afterward: REJECTED is a terminal action
    status, so this rejection may be the last thing a run was waiting
    on — see _maybe_complete_run's own docstring for the exact
    resulting run state in each case.

    Idempotent: rejecting an action that's already REJECTED returns it
    unchanged rather than raising.

    Raises:
        IncidentNotFoundError / SoarRunNotFoundError /
        SoarActionExecutionNotFoundError: via get_action.
        InvalidSoarActionTransitionError: action.status is neither
        AWAITING_APPROVAL nor (idempotently) already REJECTED — e.g.
        it was already APPROVED (rejecting an approved action is not a
        supported "undo" — Phase 1 never defined that transition).
    """
    run, action = await get_action(db, tenant_id, incident_id, run_id, action_id)

    if action.status == SoarActionStatus.REJECTED:
        return action  # idempotent no-op — a duplicate rejection request

    if action.status != SoarActionStatus.AWAITING_APPROVAL:
        raise InvalidSoarActionTransitionError(action.status, SoarActionStatus.REJECTED)

    autonomy_class = action.autonomy_class

    transition_action_status(action, SoarActionStatus.REJECTED)
    action.rejected_by_user_id = rejected_by_user_id
    action.rejected_at = datetime.now(timezone.utc)
    action.decision_reason = reason

    await db.commit()
    await _record_audit_event(
        db, tenant_id, "soar.action.rejected", run.id,
        details={
            "action_id": str(action.id),
            "action_type": action.action_type.value,
            "incident_id": str(incident_id),
            "run_id": str(run.id),
            "autonomy_class": autonomy_class.value,
            "rejected_by_user_id": str(rejected_by_user_id),
            "reason": reason,
        },
    )

    await _maybe_complete_run(db, run)
    return action


async def list_incident_audit_target_ids(db: AsyncSession, incident_id: uuid.UUID) -> tuple[list[str], list[str]]:
    """
    The audit-log target_ids belonging to one incident's SOAR activity:
    (playbook run ids, action execution ids), both as strings, since
    AuditLog.target_id is a string column.

    SOAR audit events are recorded against the entity they describe —
    target_type="soar_playbook_run" for lifecycle events
    (services/soar.py) and "soar_action_execution" for execution events
    (services/soar_execution.py) — never against the incident. That
    keeps each event attached to the thing it actually happened to, but
    it means an incident-scoped reader has to resolve the ids first;
    this is that resolution step (see
    services/incident_timeline.py::get_incident_timeline).

    Takes no tenant_id and performs no tenant check by design: it is
    reached only from a caller that has ALREADY resolved the incident
    through get_incident (so the incident is proven to belong to the
    tenant), and every id it returns is reached only by walking down
    from that incident. The audit query it feeds applies its own
    tenant filter on top, so a run id can never pull another tenant's
    events into this incident's timeline.
    """
    runs_result = await db.execute(select(SoarPlaybookRun.id).where(SoarPlaybookRun.incident_id == incident_id))
    run_ids = list(runs_result.scalars().all())
    if not run_ids:
        return [], []

    actions_result = await db.execute(
        select(SoarActionExecution.id).where(SoarActionExecution.playbook_run_id.in_(run_ids))
    )
    action_ids = list(actions_result.scalars().all())
    return [str(run_id) for run_id in run_ids], [str(action_id) for action_id in action_ids]


# ── Tenant-wide reads (Phase 3, for the /soar operations page) ──────

async def list_all_runs_with_actions(
    db: AsyncSession, tenant_id: uuid.UUID, limit: int = 100
) -> list[tuple[SoarPlaybookRun, list[SoarActionExecution]]]:
    """
    Every SOAR playbook run across the tenant's incidents, newest
    first, each with its own actions — for the tenant-wide /soar
    operations page. Unlike list_runs/get_run (scoped to one
    already-tenant-verified incident), this scopes directly via a join
    through Incident, since there's no single incident to resolve
    through first — the tenant-wide equivalent of every other SOAR
    query's own scoping pattern, not a new one. Two queries total
    (runs, then their actions batched by a single IN clause) regardless
    of how many runs exist, not one query per run.
    """
    runs_result = await db.execute(
        select(SoarPlaybookRun)
        .join(Incident, SoarPlaybookRun.incident_id == Incident.id)
        .where(Incident.tenant_id == tenant_id)
        .order_by(SoarPlaybookRun.created_at.desc())
        .limit(limit)
    )
    runs = list(runs_result.scalars().all())
    if not runs:
        return []

    run_ids = [run.id for run in runs]
    actions_result = await db.execute(
        select(SoarActionExecution)
        .where(SoarActionExecution.playbook_run_id.in_(run_ids))
        .order_by(SoarActionExecution.created_at)
    )
    actions_by_run: dict[uuid.UUID, list[SoarActionExecution]] = {}
    for action in actions_result.scalars().all():
        actions_by_run.setdefault(action.playbook_run_id, []).append(action)

    return [(run, actions_by_run.get(run.id, [])) for run in runs]
