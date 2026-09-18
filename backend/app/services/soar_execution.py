"""
SafeSOC — SOAR Action Execution Dispatcher
Turns a PENDING+AUTOMATIC or APPROVED SoarActionExecution into a real
(simulated) effect: re-checks core/soar_policy.py::classify() (never
trusts the stored autonomy_class snapshot alone), transitions the
Phase 1 state machine (services/soar.py, UNCHANGED), routes to either
a registered app/adapters/soar/*.py adapter (the 5 APPROVAL_REQUIRED
action types — unreachable from PENDING in Phase 2, reachable from
APPROVED since Phase 3's approve_action) or an internal handler (the 4
AUTOMATIC action types), persists the structured result, runs
verification, and writes both an audit trail entry
(services/audit.py, REUSED) and a real-time event
(services/realtime.py, REUSED) for every state change.

An action only ever becomes SUCCEEDED after BOTH execution and
verification succeed — never immediately after execute() returns. This
is why Phase 1's state machine needs no SUCCEEDED -> FAILED transition
(and gets none here): a verification failure is expressed as
EXECUTING -> FAILED directly, exactly like an execution failure,
because the action was never actually confirmed to have taken effect.
See core/enums.py's SoarVerificationStatus and services/soar.py's own
_ALLOWED_ACTION_TRANSITIONS, both untouched by this module.

Idempotency: execute_action() takes a Postgres advisory lock keyed on
the action id before doing anything else (mirrors
services/incidents.py::create_or_merge_incident's own technique for
the same class of problem), and treats any action not currently
PENDING or APPROVED as already handled — a second concurrent or
replayed call is a safe no-op, never a second execution.

_maybe_complete_run lives in services/soar.py, not here — see that
module's own docstring for why (reject_action needs to call it too,
and this file already imports transition_action_status from there;
having soar.py import back from here would be circular).
"""

import ipaddress
import uuid
from datetime import datetime, timezone
from typing import Callable, Optional

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.soar.sdk import SoarActionResult, SoarVerificationResult
from app.adapters.soar.sdk import registry as soar_adapter_registry
from app.core.enums import AutonomyClass, SoarActionStatus, SoarActionType, SoarVerificationStatus, UserRole
from app.core.exceptions import SoarActionExecutionNotFoundError, SoarPolicyViolationError, SoarRunNotFoundError
from app.core.security import hash_password
from app.core.soar_policy import classify
from app.models.incident import Incident
from app.models.investigation_session import InvestigationSession
from app.models.soar import SoarActionExecution, SoarPlaybookRun
from app.models.user import User
from app.services import enrichment as enrichment_service
from app.services import incidents as incidents_service
from app.services import investigation_session as investigation_session_service
from app.services.audit import record_event
from app.services.incident_evidence import get_incident_evidence
from app.services.realtime import publish_event
from app.services.soar import _maybe_complete_run, transition_action_status
from app.utils.logger import get_logger

logger = get_logger(__name__)

_SYSTEM_ACTOR_EMAIL = "soar-automation@safesoc.internal"

# Trivial, self-verifying result for an internal (non-adapter) automatic
# action that completed without raising — see execute_action's own docstring.
_INTERNAL_VERIFIED = SoarVerificationResult(verified=True, message="Internal SafeSOC operation completed without error.")


# ── System actor (see module docstring for why this exists) ─────────

async def _get_or_create_system_actor(db: AsyncSession, tenant_id: uuid.UUID) -> uuid.UUID:
    """
    A real, tenant-scoped SafeSOC platform user representing SOAR's own
    automated actions. IncidentNote.author_user_id,
    InvestigationSession.created_by_user_id, and
    InvestigationAction.created_by_user_id are all NOT NULL by design
    (models/incident.py, models/investigation_session.py — both
    UNCHANGED here) — this is the only way to satisfy that requirement
    without either fabricating a misleading human attribution or
    modifying those protected models to add a nullable/system-actor
    affordance they were never designed for. Mirrors common real-world
    SOAR practice (a dedicated automation/service identity), not a
    workaround: every note/action it creates is attributable to this
    one well-known, tenant-scoped, non-human account — never to an
    arbitrary or fabricated analyst. Its password hash is random and
    never recorded anywhere recoverable; this account can never log in
    (no login endpoint uses SOAR's own DB session concurrently with an
    attempt to authenticate as it, and its email is not discoverable
    from any API response).

    Lock-guarded (mirrors create_or_merge_incident's own advisory-lock
    technique) so two concurrent SOAR actions for a brand-new tenant's
    very first automated action can't race to create two system users.
    """
    await db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:lock_key))"), {"lock_key": f"soar_system_actor:{tenant_id}"})

    result = await db.execute(select(User).where(User.tenant_id == tenant_id, User.email == _SYSTEM_ACTOR_EMAIL))
    existing = result.scalar_one_or_none()
    if existing is not None:
        return existing.id

    system_user = User(
        tenant_id=tenant_id,
        email=_SYSTEM_ACTOR_EMAIL,
        password_hash=hash_password(uuid.uuid4().hex + uuid.uuid4().hex),
        role=UserRole.ANALYST,
    )
    db.add(system_user)
    await db.commit()
    await db.refresh(system_user)
    return system_user.id


async def _get_or_create_soar_session(db: AsyncSession, tenant_id: uuid.UUID, incident_id: uuid.UUID, actor_user_id: uuid.UUID) -> InvestigationSession:
    """
    Reuses a single dedicated investigation session for all of SOAR's
    own actions on one incident (created once, reused after), rather
    than creating a new session per action or attaching to whichever
    session an analyst happens to have open — keeps system-generated
    content in its own clearly-attributed thread instead of
    interleaving with a human analyst's live session.
    """
    sessions = await investigation_session_service.list_sessions(db, tenant_id, incident_id)
    existing = next((s for s in sessions if s.created_by_user_id == actor_user_id), None)
    if existing is not None:
        return existing
    return await investigation_session_service.create_session(db, tenant_id, incident_id, actor_user_id)


# ── Internal handlers for the 4 AUTOMATIC action types ───────────────
# Pure SafeSOC-internal operations (read evidence, write a note, look up
# TI, create an investigation action) — no external-system boundary, so
# no adapter is involved. See module docstring for the "internal
# handlers are self-verifying" reasoning.

async def _execute_collect_additional_evidence(db: AsyncSession, tenant_id: uuid.UUID, incident_id: uuid.UUID, parameters: dict) -> dict:
    evidence = await get_incident_evidence(db, tenant_id, incident_id)
    return {
        "success": True,
        "message": f"[SafeSOC] Collected {len(evidence.hosts)} host(s), {len(evidence.ips)} IP(s), and {len(evidence.users)} user(s) of evidence for this incident.",
        "hosts": [host.host_id for host in evidence.hosts],
        "ips": [ip.ip for ip in evidence.ips],
        "users": [user.user for user in evidence.users],
    }


async def _execute_enrich_indicator(db: AsyncSession, tenant_id: uuid.UUID, incident_id: uuid.UUID, parameters: dict) -> dict:
    indicator = parameters.get("indicator")
    if not indicator:
        return {"success": False, "message": "No indicator was supplied to enrich."}
    try:
        ipaddress.ip_address(indicator)
    except ValueError:
        return {"success": True, "message": f"[SafeSOC] Indicator '{indicator}' is not an IP — no enrichment provider available for it.", "indicator": indicator, "is_malicious": None}

    ti_result = await enrichment_service.enrich_indicator(db, indicator)
    return {
        "success": True,
        "message": f"[SafeSOC] Enriched indicator '{indicator}' via threat-intel providers.",
        "indicator": indicator,
        "is_malicious": ti_result.is_malicious,
        "vt_malicious": ti_result.vt_malicious,
        "vt_total": ti_result.vt_total,
        "abuse_confidence": ti_result.abuse_confidence,
        "abuse_total_reports": ti_result.abuse_total_reports,
    }


async def _execute_add_incident_note(db: AsyncSession, tenant_id: uuid.UUID, incident_id: uuid.UUID, parameters: dict) -> dict:
    note = parameters.get("note")
    if not note:
        return {"success": False, "message": "No note text was supplied."}
    actor_user_id = await _get_or_create_system_actor(db, tenant_id)
    incident_note = await incidents_service.add_note(db, tenant_id, incident_id, actor_user_id, note)
    return {"success": True, "message": "[SafeSOC] Added an automated note to this incident.", "note_id": str(incident_note.id)}


async def _execute_create_investigation_action(db: AsyncSession, tenant_id: uuid.UUID, incident_id: uuid.UUID, parameters: dict) -> dict:
    description = parameters.get("description")
    if not description:
        return {"success": False, "message": "No description was supplied."}
    actor_user_id = await _get_or_create_system_actor(db, tenant_id)
    session = await _get_or_create_soar_session(db, tenant_id, incident_id, actor_user_id)
    investigation_action = await investigation_session_service.create_action(db, tenant_id, incident_id, session.id, description, actor_user_id)
    return {
        "success": True, "message": "[SafeSOC] Created an investigation action.",
        "investigation_action_id": str(investigation_action.id), "session_id": str(session.id),
    }


_AUTOMATIC_HANDLERS: dict[SoarActionType, Callable] = {
    SoarActionType.COLLECT_ADDITIONAL_EVIDENCE: _execute_collect_additional_evidence,
    SoarActionType.ENRICH_INDICATOR: _execute_enrich_indicator,
    SoarActionType.ADD_INCIDENT_NOTE: _execute_add_incident_note,
    SoarActionType.CREATE_INVESTIGATION_ACTION: _execute_create_investigation_action,
}


def _adapter_result_to_dict(result: SoarActionResult) -> dict:
    return {
        "success": result.success, "adapter": result.adapter, "action": result.action,
        "target": result.target, "message": result.message, "state_change": result.state_change,
    }


async def _run_action(
    db: AsyncSession, tenant_id: uuid.UUID, incident_id: uuid.UUID, action_type: SoarActionType, parameters: dict
) -> tuple[dict, Optional[SoarVerificationResult]]:
    """
    Route to a registered adapter (app/adapters/soar/*.py) if one
    exists for action_type, else an internal handler. Returns
    (result_dict, verification_result) — verification_result is None
    only when execution itself failed (nothing to verify) or when no
    adapter is involved (internal handlers are self-verifying, see
    module docstring); execute_action fills in _INTERNAL_VERIFIED for
    that last case so callers never have to special-case None twice.
    """
    adapter = soar_adapter_registry.get(action_type)
    if adapter is not None:
        try:
            adapter_result = await adapter.execute(db, tenant_id, action_type, parameters)
        except Exception as e:
            logger.error("SOAR adapter execute() raised", adapter=getattr(adapter, "name", "?"), action_type=action_type.value, error_type=type(e).__name__, error=str(e))
            return {"success": False, "message": f"Adapter execution raised {type(e).__name__}: {e}"}, None

        result_dict = _adapter_result_to_dict(adapter_result)
        if not adapter_result.success:
            return result_dict, None

        try:
            verification = await adapter.verify(db, tenant_id, action_type, adapter_result)
        except Exception as e:
            logger.error("SOAR adapter verify() raised", adapter=getattr(adapter, "name", "?"), action_type=action_type.value, error_type=type(e).__name__, error=str(e))
            return result_dict, SoarVerificationResult(verified=False, message=f"Verification raised {type(e).__name__}: {e}")
        return result_dict, verification

    handler = _AUTOMATIC_HANDLERS.get(action_type)
    if handler is None:
        return {"success": False, "message": f"No adapter or internal handler is registered for action type '{action_type.value}'."}, None

    try:
        result_dict = await handler(db, tenant_id, incident_id, parameters)
    except Exception as e:
        logger.error("SOAR internal handler raised", action_type=action_type.value, error_type=type(e).__name__, error=str(e))
        return {"success": False, "message": f"Internal error: {type(e).__name__}: {e}"}, None
    return result_dict, None


# ── Audit + realtime ──────────────────────────────────────────────────

async def _record_audit_event(db: AsyncSession, tenant_id: uuid.UUID, action_name: str, action_id: uuid.UUID, details: dict) -> None:
    """Best-effort audit logging — same tolerance/reasoning as services/soar.py's own _record_audit_event."""
    try:
        await record_event(db, tenant_id, action=action_name, target_type="soar_action_execution", target_id=str(action_id), details=details)
    except Exception as e:
        logger.warning("Audit logging failed for SOAR action execution", action=action_name, action_id=str(action_id), error_type=type(e).__name__, error=str(e))


async def _emit(db: AsyncSession, tenant_id: uuid.UUID, audit_action: str, realtime_event: str, action: SoarActionExecution, incident: Incident, extra: Optional[dict] = None) -> None:
    details = {"action_type": action.action_type.value, "incident_id": str(incident.id), **(extra or {})}
    await _record_audit_event(db, tenant_id, audit_action, action.id, details)
    await publish_event(str(tenant_id), realtime_event, {"action_id": str(action.id), "incident_id": str(incident.id), "action_type": action.action_type.value})


# ── Entry point ────────────────────────────────────────────────────────

async def execute_action(db: AsyncSession, action_id: uuid.UUID) -> SoarActionExecution:
    """
    Execute one SoarActionExecution that is either PENDING+AUTOMATIC
    (Phase 2's original path: queued straight off a playbook trigger)
    or APPROVED (Phase 3: an analyst approved a formerly
    APPROVAL_REQUIRED action — services/soar.py::approve_action). Both
    paths converge on the same EXECUTING -> SUCCEEDED/FAILED logic
    below; only the entry guard differs. The only callers are
    workers/soar_worker.py (fed PENDING ids by evaluate_triggers) and
    routers/v1/soar.py's approve endpoint (fed APPROVED ids by
    approve_action) — but this function re-derives and re-checks
    classify() independently in both cases rather than trusting the
    caller or the row's own stored snapshot: the dispatcher must never
    bypass core/soar_policy.py.

    Idempotent: a second call for an action that isn't (or is no
    longer) PENDING or APPROVED — a concurrent duplicate, a replayed
    message, or simply an already-finished/not-yet-approved action —
    is a safe no-op returning the action as it currently stands, never
    a second execution.

    Raises:
        SoarActionExecutionNotFoundError: action_id doesn't exist.
        SoarRunNotFoundError: the action's own playbook_run_id
        doesn't resolve — an internal consistency failure, not a
        normal runtime path.
        SoarPolicyViolationError: for a PENDING action, action_type
        isn't classified AUTOMATIC right now; for an APPROVED action,
        it isn't classified APPROVAL_REQUIRED right now (a policy
        change since it was queued/approved). Either way this is the
        hard safety backstop: even if a bug somehow queued or approved
        something it shouldn't have, this raises instead of running it.
    """
    await db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:lock_key))"), {"lock_key": f"soar_action:{action_id}"})

    result = await db.execute(select(SoarActionExecution).where(SoarActionExecution.id == action_id))
    action = result.scalar_one_or_none()
    if action is None:
        raise SoarActionExecutionNotFoundError(action_id)

    if action.status not in (SoarActionStatus.PENDING, SoarActionStatus.APPROVED):
        logger.info(
            "SOAR action is not in an executable state — skipping (already handled, in flight, or not yet approved)",
            action_id=str(action_id), status=action.status.value,
        )
        return action

    run_result = await db.execute(select(SoarPlaybookRun).where(SoarPlaybookRun.id == action.playbook_run_id))
    run = run_result.scalar_one_or_none()
    if run is None:
        raise SoarRunNotFoundError(action.playbook_run_id)

    incident_result = await db.execute(select(Incident).where(Incident.id == run.incident_id))
    incident = incident_result.scalar_one_or_none()
    if incident is None:
        raise SoarRunNotFoundError(run.id)
    tenant_id = incident.tenant_id

    # Fail-closed policy re-check — the authority is core/soar_policy.py
    # right now, never the row's own (possibly stale) stored snapshot.
    # Which classification is required depends on which entry path this
    # is: PENDING must still be AUTOMATIC (Phase 2, unchanged); APPROVED
    # must still be APPROVAL_REQUIRED (Phase 3 — an analyst approved it
    # as a gated action; it would be a policy inconsistency, not a
    # promotion, if it were now AUTOMATIC instead).
    autonomy_class = classify(action.action_type)
    expected_autonomy_class = AutonomyClass.AUTOMATIC if action.status == SoarActionStatus.PENDING else AutonomyClass.APPROVAL_REQUIRED
    if autonomy_class != expected_autonomy_class:
        logger.warning(
            "Refusing to execute a SOAR action whose current policy classification doesn't match its entry path",
            action_id=str(action_id), action_type=action.action_type.value,
            entry_status=action.status.value, autonomy_class=autonomy_class.value,
        )
        raise SoarPolicyViolationError(action.action_type, autonomy_class)

    transition_action_status(action, SoarActionStatus.EXECUTING)
    action.executed_at = datetime.now(timezone.utc)
    await db.commit()
    await _emit(db, tenant_id, "soar.action.started", "soar_action_started", action, incident)

    result_dict, verification = await _run_action(db, tenant_id, incident.id, action.action_type, action.parameters)
    action.result = result_dict

    if not result_dict.get("success"):
        transition_action_status(action, SoarActionStatus.FAILED)
        await db.commit()
        await _emit(db, tenant_id, "soar.action.failed", "soar_action_failed", action, incident, {"result": result_dict})
        await _maybe_complete_run(db, run)
        return action

    verification = verification or _INTERNAL_VERIFIED
    action.verification_status = SoarVerificationStatus.VERIFIED if verification.verified else SoarVerificationStatus.VERIFICATION_FAILED
    action.verified_at = datetime.now(timezone.utc)

    if verification.verified:
        transition_action_status(action, SoarActionStatus.SUCCEEDED)
        await db.commit()
        await _emit(db, tenant_id, "soar.action.succeeded", "soar_action_succeeded", action, incident, {"result": result_dict})
        await _emit(db, tenant_id, "soar.action.verified", "soar_action_verified", action, incident)
    else:
        # Executed, but could not be confirmed — never marked SUCCEEDED.
        # The incident must not be treated as remediated on the strength
        # of an execution result alone.
        transition_action_status(action, SoarActionStatus.FAILED)
        await db.commit()
        await _emit(db, tenant_id, "soar.action.verification_failed", "soar_action_verification_failed", action, incident, {"message": verification.message})
        await _emit(db, tenant_id, "soar.action.failed", "soar_action_failed", action, incident, {"result": result_dict, "reason": "verification_failed"})

    await _maybe_complete_run(db, run)
    return action
