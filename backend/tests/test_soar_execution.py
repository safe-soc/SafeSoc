"""
SafeSOC — SOAR Execution Dispatcher Tests
services/soar_execution.py::execute_action is the one function that
turns a PENDING action into a real (simulated) effect — these tests
cover its control flow (automatic executes, approval-required is
refused, success/failure/verification-failure persistence, idempotent
duplicate/concurrent calls) and its own internal handlers for the 4
AUTOMATIC action types, each mocking only its own direct dependency
(boundary-mocked, same convention as every other service test in this
suite).
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from app.core.enums import (
    AutonomyClass,
    IncidentStatus,
    RecommendationSource,
    SoarActionStatus,
    SoarActionType,
    SoarRunStatus,
    SoarTriggerSource,
    SoarVerificationStatus,
)
from app.core.exceptions import SoarActionExecutionNotFoundError, SoarPolicyViolationError, SoarRunNotFoundError
from app.models.incident import Incident
from app.models.soar import SoarActionExecution, SoarPlaybookRun
from app.services import soar_execution


# ── Fake session dispatch ────────────────────────────────────────────

class _Result:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None


class _FakeExecutionSession:
    """
    Serves the fixed query sequence execute_action/_maybe_complete_run
    issue: advisory lock (ignored) -> fetch action by id -> fetch run
    by id -> fetch incident by id -> [handler runs, boundary-mocked
    separately] -> fetch every action for the run (_maybe_complete_run).
    The two SoarActionExecution queries are disambiguated by call
    order; returning the SAME action object both times means mutations
    the dispatcher makes are visible on the second read, exactly like a
    real session would show its own uncommitted writes.
    """

    def __init__(self, action, run, incident, sibling_actions=None):
        self.action = action
        self.run = run
        self.incident = incident
        self.sibling_actions = sibling_actions if sibling_actions is not None else [action]
        self._action_query_count = 0
        self.committed_count = 0

    async def execute(self, stmt, params=None):
        if params is not None and "lock_key" in params:
            return None
        target = getattr(stmt, "column_descriptions", [{}])[0].get("type") if hasattr(stmt, "column_descriptions") else None
        if target is SoarActionExecution:
            self._action_query_count += 1
            return _Result([self.action]) if self._action_query_count == 1 else _Result(self.sibling_actions)
        if target is SoarPlaybookRun:
            return _Result([self.run])
        if target is Incident:
            return _Result([self.incident])
        return _Result([])

    async def commit(self):
        self.committed_count += 1


def _incident(tenant_id) -> Incident:
    return Incident(id=uuid.uuid4(), tenant_id=tenant_id, status=IncidentStatus.OPEN, alert_ids=[], category=None, confidence=None, tags=[], created_at=datetime.now(timezone.utc))


def _run(incident_id) -> SoarPlaybookRun:
    return SoarPlaybookRun(id=uuid.uuid4(), incident_id=incident_id, playbook_id="pb-x", triggered_by=SoarTriggerSource.AUTO_TRIGGER, status=SoarRunStatus.RUNNING, created_at=datetime.now(timezone.utc))


def _action(run_id, action_type=SoarActionType.ADD_INCIDENT_NOTE, autonomy_class=AutonomyClass.AUTOMATIC, status=SoarActionStatus.PENDING) -> SoarActionExecution:
    return SoarActionExecution(
        id=uuid.uuid4(), playbook_run_id=run_id, action_type=action_type, parameters={"note": "x"},
        autonomy_class=autonomy_class, recommended_by=RecommendationSource.PLAYBOOK_AUTO, status=status,
        verification_status=SoarVerificationStatus.NOT_VERIFIED, created_at=datetime.now(timezone.utc),
    )


@pytest.fixture(autouse=True)
def _mock_audit_and_realtime(monkeypatch):
    monkeypatch.setattr(soar_execution, "record_event", AsyncMock())
    monkeypatch.setattr(soar_execution, "publish_event", AsyncMock())


# ── Automatic actions execute ────────────────────────────────────────

@pytest.mark.asyncio
async def test_automatic_action_executes_and_succeeds(monkeypatch):
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id)
    run = _run(incident.id)
    action = _action(run.id)
    db = _FakeExecutionSession(action, run, incident)
    monkeypatch.setattr(soar_execution, "_AUTOMATIC_HANDLERS", {SoarActionType.ADD_INCIDENT_NOTE: AsyncMock(return_value={"success": True, "message": "ok"})})

    result = await soar_execution.execute_action(db, action.id)

    assert result.status == SoarActionStatus.SUCCEEDED
    assert result.verification_status == SoarVerificationStatus.VERIFIED
    assert result.result == {"success": True, "message": "ok"}
    assert result.executed_at is not None
    assert result.verified_at is not None


@pytest.mark.asyncio
async def test_automatic_action_that_fails_execution_becomes_failed_not_verified(monkeypatch):
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id)
    run = _run(incident.id)
    action = _action(run.id)
    db = _FakeExecutionSession(action, run, incident)
    monkeypatch.setattr(soar_execution, "_AUTOMATIC_HANDLERS", {SoarActionType.ADD_INCIDENT_NOTE: AsyncMock(return_value={"success": False, "message": "no note text"})})

    result = await soar_execution.execute_action(db, action.id)

    assert result.status == SoarActionStatus.FAILED
    assert result.verification_status == SoarVerificationStatus.NOT_VERIFIED  # never attempted — execution itself failed


@pytest.mark.asyncio
async def test_handler_raising_an_exception_is_caught_and_becomes_a_failed_result(monkeypatch):
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id)
    run = _run(incident.id)
    action = _action(run.id)
    db = _FakeExecutionSession(action, run, incident)
    monkeypatch.setattr(soar_execution, "_AUTOMATIC_HANDLERS", {SoarActionType.ADD_INCIDENT_NOTE: AsyncMock(side_effect=RuntimeError("boom"))})

    result = await soar_execution.execute_action(db, action.id)

    assert result.status == SoarActionStatus.FAILED
    assert "boom" in result.result["message"]


# ── Verification failure ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_adapter_routed_action_that_fails_verification_becomes_failed_never_succeeded(monkeypatch):
    """
    An adapter can succeed at execute() but fail verify() — the action
    must land on FAILED, never SUCCEEDED (task's own §9 requirement).

    No AUTOMATIC action type has an adapter registered in Phase 2 (only
    the 5 APPROVAL_REQUIRED ones do), so this adapter-execution branch
    is genuinely unreachable via the real dispatcher right now — it's
    forward-compatible code a future approval workflow (Phase 3) will
    exercise for real. To test it in isolation here, classify() itself
    is patched to say AUTOMATIC for this one call, on top of the row's
    own autonomy_class — both must agree for execute_action to proceed
    at all, which is itself proof the policy re-check is load-bearing,
    not decorative.
    """
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id)
    run = _run(incident.id)
    action = _action(run.id, action_type=SoarActionType.ISOLATE_ENDPOINT, autonomy_class=AutonomyClass.AUTOMATIC)
    db = _FakeExecutionSession(action, run, incident)
    monkeypatch.setattr(soar_execution, "classify", lambda action_type: AutonomyClass.AUTOMATIC)

    from app.adapters.soar.sdk import SoarActionResult, SoarVerificationResult

    fake_adapter = AsyncMock()
    fake_adapter.execute = AsyncMock(return_value=SoarActionResult(success=True, adapter="simulated_edr", action="isolate_endpoint", target="DESKTOP-042", message="ok", state_change={"status": "isolated"}))
    fake_adapter.verify = AsyncMock(return_value=SoarVerificationResult(verified=False, message="synthetic state mismatch"))
    monkeypatch.setattr(soar_execution.soar_adapter_registry, "get", lambda action_type: fake_adapter)

    result = await soar_execution.execute_action(db, action.id)

    assert result.status == SoarActionStatus.FAILED  # never SUCCEEDED
    assert result.verification_status == SoarVerificationStatus.VERIFICATION_FAILED
    assert result.result["success"] is True  # execution itself DID succeed — only verification failed


@pytest.mark.asyncio
async def test_adapter_routed_action_that_passes_verification_succeeds(monkeypatch):
    """Same forward-compatibility note as the test above — see its docstring."""
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id)
    run = _run(incident.id)
    action = _action(run.id, action_type=SoarActionType.BLOCK_INDICATOR, autonomy_class=AutonomyClass.AUTOMATIC)
    db = _FakeExecutionSession(action, run, incident)
    monkeypatch.setattr(soar_execution, "classify", lambda action_type: AutonomyClass.AUTOMATIC)

    from app.adapters.soar.sdk import SoarActionResult, SoarVerificationResult

    fake_adapter = AsyncMock()
    fake_adapter.execute = AsyncMock(return_value=SoarActionResult(success=True, adapter="simulated_firewall", action="block_indicator", target="1.2.3.4", message="ok", state_change={"indicator": "1.2.3.4", "status": "blocked"}))
    fake_adapter.verify = AsyncMock(return_value=SoarVerificationResult(verified=True, message="confirmed"))
    monkeypatch.setattr(soar_execution.soar_adapter_registry, "get", lambda action_type: fake_adapter)

    result = await soar_execution.execute_action(db, action.id)

    assert result.status == SoarActionStatus.SUCCEEDED
    assert result.verification_status == SoarVerificationStatus.VERIFIED


# ── Security: policy cannot be bypassed ──────────────────────────────

@pytest.mark.asyncio
async def test_approval_required_action_is_refused_even_if_somehow_queued(monkeypatch):
    """
    The hard safety backstop: even if an APPROVAL_REQUIRED action
    somehow reached PENDING and got a call to execute_action (it never
    should — evaluate_triggers only ever queues AUTOMATIC ids), the
    dispatcher's own fresh classify() call refuses it. No mutation, no
    adapter call.
    """
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id)
    run = _run(incident.id)
    action = _action(run.id, action_type=SoarActionType.ISOLATE_ENDPOINT, autonomy_class=AutonomyClass.APPROVAL_REQUIRED)
    db = _FakeExecutionSession(action, run, incident)

    with pytest.raises(SoarPolicyViolationError):
        await soar_execution.execute_action(db, action.id)

    assert action.status == SoarActionStatus.PENDING  # untouched
    assert db.committed_count == 0


@pytest.mark.asyncio
async def test_stored_autonomy_class_is_never_trusted_over_a_fresh_policy_check(monkeypatch):
    """Even if the row's OWN stored snapshot claims AUTOMATIC (e.g. corrupted/stale data), a fresh classify() disagreeing must still win."""
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id)
    run = _run(incident.id)
    # Stored snapshot says AUTOMATIC, but the real action_type (ISOLATE_ENDPOINT) is APPROVAL_REQUIRED.
    action = _action(run.id, action_type=SoarActionType.ISOLATE_ENDPOINT, autonomy_class=AutonomyClass.AUTOMATIC)
    db = _FakeExecutionSession(action, run, incident)

    with pytest.raises(SoarPolicyViolationError):
        await soar_execution.execute_action(db, action.id)


def test_soar_worker_task_is_registered_with_celery():
    """Regression guard: app.workers.soar_worker must be in celery_app.py's `include` list, or the real worker process silently never learns about execute_soar_action even though it's queueable from the producer side (correlation_worker.py's own .delay() calls)."""
    from app.tasks.celery_app import celery_app

    assert "app.workers.soar_worker.execute_soar_action" in celery_app.tasks


@pytest.mark.asyncio
async def test_no_execute_or_force_execution_http_endpoint_exists():
    """There is no client-facing path to force execution at all in Phase 2 — the only caller is the Celery worker, itself only ever fed AUTOMATIC action ids by evaluate_triggers."""
    from app.main import app

    paths = {getattr(route, "path", "") for route in app.routes}
    assert not any("execute" in path for path in paths if "/soar" in path)


# ── Idempotency / duplicate / concurrent execution ───────────────────

@pytest.mark.asyncio
async def test_duplicate_execution_of_an_already_succeeded_action_is_a_no_op(monkeypatch):
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id)
    run = _run(incident.id)
    action = _action(run.id, status=SoarActionStatus.SUCCEEDED)
    db = _FakeExecutionSession(action, run, incident)
    handler = AsyncMock()
    monkeypatch.setattr(soar_execution, "_AUTOMATIC_HANDLERS", {SoarActionType.ADD_INCIDENT_NOTE: handler})

    result = await soar_execution.execute_action(db, action.id)

    assert result is action
    assert result.status == SoarActionStatus.SUCCEEDED
    handler.assert_not_called()
    assert db.committed_count == 0


@pytest.mark.asyncio
async def test_concurrent_replay_cannot_execute_twice(monkeypatch):
    """Simulates two sequential calls for the same action (standing in for a concurrent replay serialized by the real advisory lock) — the second must see the first's mutation and skip."""
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id)
    run = _run(incident.id)
    action = _action(run.id)
    db = _FakeExecutionSession(action, run, incident)
    handler = AsyncMock(return_value={"success": True, "message": "ok"})
    monkeypatch.setattr(soar_execution, "_AUTOMATIC_HANDLERS", {SoarActionType.ADD_INCIDENT_NOTE: handler})

    first = await soar_execution.execute_action(db, action.id)
    second = await soar_execution.execute_action(db, action.id)

    assert first.status == SoarActionStatus.SUCCEEDED
    assert second.status == SoarActionStatus.SUCCEEDED
    handler.assert_called_once()  # only the FIRST call actually ran the handler


# ── Not found / internal consistency ─────────────────────────────────

@pytest.mark.asyncio
async def test_execute_action_raises_for_an_unknown_action_id():
    db = _FakeExecutionSession(action=None, run=None, incident=None, sibling_actions=[])
    db.action = None

    class _EmptySession(_FakeExecutionSession):
        async def execute(self, stmt, params=None):
            if params is not None and "lock_key" in params:
                return None
            return _Result([])

    with pytest.raises(SoarActionExecutionNotFoundError):
        await soar_execution.execute_action(_EmptySession(None, None, None), uuid.uuid4())


# ── Cross-tenant / cross-incident derivation (structural) ────────────

def test_execute_action_signature_takes_only_an_action_id():
    """
    Security-by-construction: there is no tenant_id/incident_id
    parameter to mismatch or spoof — execute_action derives both from
    the action's own playbook_run -> incident chain in the database,
    every time, never from a caller-supplied value.
    """
    import inspect

    params = list(inspect.signature(soar_execution.execute_action).parameters)
    assert params == ["db", "action_id"]


@pytest.mark.asyncio
async def test_tenant_id_used_for_system_actor_is_derived_from_the_incident_not_supplied(monkeypatch):
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id)
    run = _run(incident.id)
    action = _action(run.id, action_type=SoarActionType.ADD_INCIDENT_NOTE)
    db = _FakeExecutionSession(action, run, incident)

    captured_tenant_ids = []

    async def _fake_handler(db, tenant_id_arg, incident_id_arg, parameters):
        captured_tenant_ids.append(tenant_id_arg)
        return {"success": True, "message": "ok"}

    monkeypatch.setattr(soar_execution, "_AUTOMATIC_HANDLERS", {SoarActionType.ADD_INCIDENT_NOTE: _fake_handler})

    await soar_execution.execute_action(db, action.id)

    assert captured_tenant_ids == [incident.tenant_id]  # exactly the incident's own tenant, nothing else


# ── Internal handlers (each mocking only its own direct dependency) ─

@pytest.mark.asyncio
async def test_collect_additional_evidence_handler_summarizes_real_evidence(monkeypatch):
    from app.services.incident_evidence import HostEntity, IncidentEvidence, IPEntity, UserEntity

    evidence = IncidentEvidence(incident_id=uuid.uuid4(), hosts=[HostEntity(host_id="DESKTOP-042", alert_count=1)], ips=[IPEntity(ip="1.2.3.4", roles=["source"], alert_count=1)], users=[UserEntity(user="tom.thompson", alert_count=1)], cloud_resources=[])
    monkeypatch.setattr(soar_execution, "get_incident_evidence", AsyncMock(return_value=evidence))

    result = await soar_execution._execute_collect_additional_evidence(None, uuid.uuid4(), uuid.uuid4(), {})

    assert result["success"] is True
    assert result["hosts"] == ["DESKTOP-042"]


@pytest.mark.asyncio
async def test_enrich_indicator_handler_returns_ti_result(monkeypatch):
    from app.schemas.log import TIResult

    monkeypatch.setattr(soar_execution.enrichment_service, "enrich_indicator", AsyncMock(return_value=TIResult(is_malicious=True, vt_malicious=5, vt_total=70)))

    result = await soar_execution._execute_enrich_indicator(None, uuid.uuid4(), uuid.uuid4(), {"indicator": "203.0.113.5"})

    assert result["success"] is True
    assert result["is_malicious"] is True


@pytest.mark.asyncio
async def test_enrich_indicator_handler_fails_without_an_indicator():
    result = await soar_execution._execute_enrich_indicator(None, uuid.uuid4(), uuid.uuid4(), {})
    assert result["success"] is False


@pytest.mark.asyncio
async def test_enrich_indicator_handler_handles_a_non_ip_indicator_without_calling_ti_providers(monkeypatch):
    enrich_mock = AsyncMock()
    monkeypatch.setattr(soar_execution.enrichment_service, "enrich_indicator", enrich_mock)

    result = await soar_execution._execute_enrich_indicator(None, uuid.uuid4(), uuid.uuid4(), {"indicator": "not-an-ip.example"})

    assert result["success"] is True
    enrich_mock.assert_not_called()


@pytest.mark.asyncio
async def test_add_incident_note_handler_creates_a_real_note_via_the_existing_service(monkeypatch):
    from app.models.incident import IncidentNote

    note = IncidentNote(id=uuid.uuid4(), incident_id=uuid.uuid4(), author_user_id=uuid.uuid4(), body="x", created_at=datetime.now(timezone.utc))
    monkeypatch.setattr(soar_execution, "_get_or_create_system_actor", AsyncMock(return_value=uuid.uuid4()))
    add_note_mock = AsyncMock(return_value=note)
    monkeypatch.setattr(soar_execution.incidents_service, "add_note", add_note_mock)

    result = await soar_execution._execute_add_incident_note(None, uuid.uuid4(), uuid.uuid4(), {"note": "Automated note"})

    assert result["success"] is True
    add_note_mock.assert_called_once()
    assert add_note_mock.call_args.args[-1] == "Automated note"


@pytest.mark.asyncio
async def test_add_incident_note_handler_fails_without_note_text():
    result = await soar_execution._execute_add_incident_note(None, uuid.uuid4(), uuid.uuid4(), {})
    assert result["success"] is False


@pytest.mark.asyncio
async def test_create_investigation_action_handler_reuses_existing_session_service(monkeypatch):
    from app.core.enums import InvestigationActionStatus
    from app.models.investigation_session import InvestigationAction, InvestigationSession

    actor_id = uuid.uuid4()
    session = InvestigationSession(id=uuid.uuid4(), incident_id=uuid.uuid4(), created_by_user_id=actor_id, created_at=datetime.now(timezone.utc))
    created_action = InvestigationAction(id=uuid.uuid4(), session_id=session.id, description="x", status=InvestigationActionStatus.OPEN, created_by_user_id=actor_id, created_at=datetime.now(timezone.utc))

    monkeypatch.setattr(soar_execution, "_get_or_create_system_actor", AsyncMock(return_value=actor_id))
    monkeypatch.setattr(soar_execution, "_get_or_create_soar_session", AsyncMock(return_value=session))
    create_action_mock = AsyncMock(return_value=created_action)
    monkeypatch.setattr(soar_execution.investigation_session_service, "create_action", create_action_mock)

    result = await soar_execution._execute_create_investigation_action(None, uuid.uuid4(), uuid.uuid4(), {"description": "Review this"})

    assert result["success"] is True
    assert result["investigation_action_id"] == str(created_action.id)
    create_action_mock.assert_called_once()


@pytest.mark.asyncio
async def test_get_or_create_soar_session_reuses_an_existing_system_session(monkeypatch):
    from app.models.investigation_session import InvestigationSession

    actor_id = uuid.uuid4()
    existing = InvestigationSession(id=uuid.uuid4(), incident_id=uuid.uuid4(), created_by_user_id=actor_id, created_at=datetime.now(timezone.utc))
    other = InvestigationSession(id=uuid.uuid4(), incident_id=uuid.uuid4(), created_by_user_id=uuid.uuid4(), created_at=datetime.now(timezone.utc))
    monkeypatch.setattr(soar_execution.investigation_session_service, "list_sessions", AsyncMock(return_value=[other, existing]))
    create_mock = AsyncMock()
    monkeypatch.setattr(soar_execution.investigation_session_service, "create_session", create_mock)

    result = await soar_execution._get_or_create_soar_session(None, uuid.uuid4(), uuid.uuid4(), actor_id)

    assert result is existing
    create_mock.assert_not_called()
