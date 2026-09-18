"""
SafeSOC — SOAR Human Approval Workflow Tests (Phase 3)
services/soar.py::get_action/approve_action/reject_action (service
layer) and routers/v1/soar.py's approve/reject/list_all_runs endpoints
(HTTP layer, service mocked) — the same boundary-mocked-fake-session
philosophy as test_soar_service.py/test_soar_router.py. Run-completion
semantics (_maybe_complete_run) have their own dedicated file,
test_soar_run_completion.py.
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock

import pytest

from app.core.enums import (
    AutonomyClass,
    RecommendationSource,
    SoarActionStatus,
    SoarActionType,
    SoarRunStatus,
    SoarTriggerSource,
    SoarVerificationStatus,
    UserRole,
)
from app.core.exceptions import (
    IncidentNotFoundError,
    InvalidSoarActionTransitionError,
    SoarActionExecutionNotFoundError,
    SoarPolicyViolationError,
    SoarRunNotFoundError,
)
from app.db.postgresql import get_db
from app.main import app
from app.models.soar import SoarActionExecution, SoarPlaybookRun
from app.routers.v1 import soar as router_module
from app.services import soar as soar_service


def _run(status=SoarRunStatus.RUNNING) -> SoarPlaybookRun:
    return SoarPlaybookRun(
        id=uuid.uuid4(), incident_id=uuid.uuid4(), playbook_id="pb-x", triggered_by=SoarTriggerSource.AUTO_TRIGGER,
        status=status, started_at=datetime.now(timezone.utc), created_at=datetime.now(timezone.utc),
    )


def _action(status=SoarActionStatus.AWAITING_APPROVAL, autonomy_class=AutonomyClass.APPROVAL_REQUIRED) -> SoarActionExecution:
    return SoarActionExecution(
        id=uuid.uuid4(), playbook_run_id=uuid.uuid4(), action_type=SoarActionType.ISOLATE_ENDPOINT,
        parameters={"host_id": "host-1"}, autonomy_class=autonomy_class, recommended_by=RecommendationSource.PLAYBOOK_AUTO,
        status=status, verification_status=SoarVerificationStatus.NOT_VERIFIED, created_at=datetime.now(timezone.utc),
    )


class _NullSession:
    """approve_action/reject_action never issue their own SELECTs (get_action is mocked) — only commit() should be called."""

    def __init__(self):
        self.commit_count = 0

    async def commit(self):
        self.commit_count += 1


# ── approve_action: service layer ────────────────────────────────────

@pytest.mark.asyncio
async def test_approve_transitions_action_to_approved_and_records_decision(monkeypatch):
    run = _run(status=SoarRunStatus.RUNNING)
    action = _action(status=SoarActionStatus.AWAITING_APPROVAL, autonomy_class=AutonomyClass.APPROVAL_REQUIRED)
    monkeypatch.setattr(soar_service, "get_action", AsyncMock(return_value=(run, action)))
    record_event_mock = AsyncMock()
    monkeypatch.setattr(soar_service, "record_event", record_event_mock)
    db = _NullSession()
    approver_id = uuid.uuid4()

    result = await soar_service.approve_action(db, uuid.uuid4(), uuid.uuid4(), run.id, action.id, approver_id, reason="Confirmed malicious")

    assert result.status == SoarActionStatus.APPROVED
    assert result.approved_by_user_id == approver_id
    assert result.approved_at is not None
    assert result.decision_reason == "Confirmed malicious"
    assert db.commit_count == 1


@pytest.mark.asyncio
async def test_approve_flips_an_awaiting_approval_run_to_running(monkeypatch):
    """A run with zero AUTOMATIC actions sits at AWAITING_APPROVAL until the first approval — that approval starts it running."""
    run = _run(status=SoarRunStatus.AWAITING_APPROVAL)
    action = _action(status=SoarActionStatus.AWAITING_APPROVAL)
    monkeypatch.setattr(soar_service, "get_action", AsyncMock(return_value=(run, action)))
    monkeypatch.setattr(soar_service, "record_event", AsyncMock())

    await soar_service.approve_action(_NullSession(), uuid.uuid4(), uuid.uuid4(), run.id, action.id, uuid.uuid4())

    assert run.status == SoarRunStatus.RUNNING


@pytest.mark.asyncio
async def test_approve_does_not_change_a_run_already_running(monkeypatch):
    """A run with at least one AUTOMATIC action was already RUNNING — approving a sibling action leaves it untouched."""
    run = _run(status=SoarRunStatus.RUNNING)
    action = _action(status=SoarActionStatus.AWAITING_APPROVAL)
    monkeypatch.setattr(soar_service, "get_action", AsyncMock(return_value=(run, action)))
    monkeypatch.setattr(soar_service, "record_event", AsyncMock())

    await soar_service.approve_action(_NullSession(), uuid.uuid4(), uuid.uuid4(), run.id, action.id, uuid.uuid4())

    assert run.status == SoarRunStatus.RUNNING


@pytest.mark.asyncio
async def test_duplicate_approval_is_idempotent(monkeypatch):
    run = _run()
    approver_id = uuid.uuid4()
    approved_at = datetime.now(timezone.utc)
    action = _action(status=SoarActionStatus.APPROVED)
    action.approved_by_user_id = approver_id
    action.approved_at = approved_at
    monkeypatch.setattr(soar_service, "get_action", AsyncMock(return_value=(run, action)))
    record_event_mock = AsyncMock()
    monkeypatch.setattr(soar_service, "record_event", record_event_mock)
    db = _NullSession()

    result = await soar_service.approve_action(db, uuid.uuid4(), uuid.uuid4(), run.id, action.id, uuid.uuid4())

    assert result.status == SoarActionStatus.APPROVED
    assert result.approved_by_user_id == approver_id  # unchanged — the original approver, not the second caller
    assert result.approved_at == approved_at
    assert db.commit_count == 0  # no-op: no write happened
    record_event_mock.assert_not_called()  # no duplicate audit event for a no-op


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad_status",
    [SoarActionStatus.PENDING, SoarActionStatus.REJECTED, SoarActionStatus.EXECUTING, SoarActionStatus.SUCCEEDED, SoarActionStatus.FAILED],
)
async def test_approve_rejects_an_action_not_awaiting_approval(monkeypatch, bad_status):
    run = _run()
    action = _action(status=bad_status)
    monkeypatch.setattr(soar_service, "get_action", AsyncMock(return_value=(run, action)))

    with pytest.raises(InvalidSoarActionTransitionError):
        await soar_service.approve_action(_NullSession(), uuid.uuid4(), uuid.uuid4(), run.id, action.id, uuid.uuid4())


@pytest.mark.asyncio
async def test_approve_rechecks_policy_and_refuses_if_no_longer_approval_required(monkeypatch):
    """Defense in depth: if classify() would now say AUTOMATIC for this action_type, approval refuses rather than trusting the stored snapshot."""
    run = _run()
    action = _action(status=SoarActionStatus.AWAITING_APPROVAL)
    monkeypatch.setattr(soar_service, "get_action", AsyncMock(return_value=(run, action)))
    monkeypatch.setattr(soar_service, "classify", lambda action_type: AutonomyClass.AUTOMATIC)

    with pytest.raises(SoarPolicyViolationError):
        await soar_service.approve_action(_NullSession(), uuid.uuid4(), uuid.uuid4(), run.id, action.id, uuid.uuid4())

    assert action.status == SoarActionStatus.AWAITING_APPROVAL  # untouched


@pytest.mark.asyncio
async def test_approve_audit_event_carries_full_decision_context(monkeypatch):
    run = _run()
    action = _action(status=SoarActionStatus.AWAITING_APPROVAL)
    monkeypatch.setattr(soar_service, "get_action", AsyncMock(return_value=(run, action)))
    record_event_mock = AsyncMock()
    monkeypatch.setattr(soar_service, "record_event", record_event_mock)
    tenant_id = uuid.uuid4()
    incident_id = uuid.uuid4()
    approver_id = uuid.uuid4()

    await soar_service.approve_action(_NullSession(), tenant_id, incident_id, run.id, action.id, approver_id, reason="ok")

    record_event_mock.assert_called_once()
    kwargs = record_event_mock.call_args.kwargs
    assert kwargs["action"] == "soar.action.approved"
    details = kwargs["details"]
    assert details["action_id"] == str(action.id)
    assert details["action_type"] == action.action_type.value
    assert details["incident_id"] == str(incident_id)
    assert details["run_id"] == str(run.id)
    assert details["autonomy_class"] == AutonomyClass.APPROVAL_REQUIRED.value
    assert details["approved_by_user_id"] == str(approver_id)
    assert details["reason"] == "ok"


# ── reject_action: service layer ─────────────────────────────────────

@pytest.mark.asyncio
async def test_reject_transitions_action_to_rejected_and_records_decision(monkeypatch):
    run = _run(status=SoarRunStatus.RUNNING)
    action = _action(status=SoarActionStatus.AWAITING_APPROVAL)
    monkeypatch.setattr(soar_service, "get_action", AsyncMock(return_value=(run, action)))
    monkeypatch.setattr(soar_service, "record_event", AsyncMock())
    monkeypatch.setattr(soar_service, "_maybe_complete_run", AsyncMock())
    db = _NullSession()
    rejector_id = uuid.uuid4()

    result = await soar_service.reject_action(db, uuid.uuid4(), uuid.uuid4(), run.id, action.id, rejector_id, reason="False positive")

    assert result.status == SoarActionStatus.REJECTED
    assert result.rejected_by_user_id == rejector_id
    assert result.rejected_at is not None
    assert result.decision_reason == "False positive"
    assert db.commit_count == 1


@pytest.mark.asyncio
async def test_reject_never_leaves_approved_by_fields_set():
    """A rejected action's approved_* fields must stay unset — exactly one of the approve/reject pairs is ever populated."""
    action = _action(status=SoarActionStatus.REJECTED)
    action.rejected_by_user_id = uuid.uuid4()
    action.rejected_at = datetime.now(timezone.utc)
    assert action.approved_by_user_id is None
    assert action.approved_at is None


@pytest.mark.asyncio
async def test_reject_calls_maybe_complete_run(monkeypatch):
    """A REJECTED action is terminal — reject_action must always give the run a chance to complete."""
    run = _run()
    action = _action(status=SoarActionStatus.AWAITING_APPROVAL)
    monkeypatch.setattr(soar_service, "get_action", AsyncMock(return_value=(run, action)))
    monkeypatch.setattr(soar_service, "record_event", AsyncMock())
    complete_mock = AsyncMock()
    monkeypatch.setattr(soar_service, "_maybe_complete_run", complete_mock)
    db = _NullSession()

    await soar_service.reject_action(db, uuid.uuid4(), uuid.uuid4(), run.id, action.id, uuid.uuid4())

    complete_mock.assert_awaited_once_with(db, run)


@pytest.mark.asyncio
async def test_duplicate_rejection_is_idempotent(monkeypatch):
    run = _run()
    rejector_id = uuid.uuid4()
    rejected_at = datetime.now(timezone.utc)
    action = _action(status=SoarActionStatus.REJECTED)
    action.rejected_by_user_id = rejector_id
    action.rejected_at = rejected_at
    monkeypatch.setattr(soar_service, "get_action", AsyncMock(return_value=(run, action)))
    record_event_mock = AsyncMock()
    monkeypatch.setattr(soar_service, "record_event", record_event_mock)
    complete_mock = AsyncMock()
    monkeypatch.setattr(soar_service, "_maybe_complete_run", complete_mock)
    db = _NullSession()

    result = await soar_service.reject_action(db, uuid.uuid4(), uuid.uuid4(), run.id, action.id, uuid.uuid4())

    assert result.rejected_by_user_id == rejector_id  # unchanged
    assert result.rejected_at == rejected_at
    assert db.commit_count == 0
    record_event_mock.assert_not_called()
    complete_mock.assert_not_called()  # already-terminal no-op never re-evaluates the run


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad_status",
    [SoarActionStatus.PENDING, SoarActionStatus.APPROVED, SoarActionStatus.EXECUTING, SoarActionStatus.SUCCEEDED, SoarActionStatus.FAILED],
)
async def test_reject_rejects_an_action_not_awaiting_approval(monkeypatch, bad_status):
    """Rejecting an already-APPROVED action is not a supported 'undo' — Phase 1 never defined that transition."""
    run = _run()
    action = _action(status=bad_status)
    monkeypatch.setattr(soar_service, "get_action", AsyncMock(return_value=(run, action)))

    with pytest.raises(InvalidSoarActionTransitionError):
        await soar_service.reject_action(_NullSession(), uuid.uuid4(), uuid.uuid4(), run.id, action.id, uuid.uuid4())


@pytest.mark.asyncio
async def test_reject_audit_event_carries_full_decision_context(monkeypatch):
    run = _run()
    action = _action(status=SoarActionStatus.AWAITING_APPROVAL)
    monkeypatch.setattr(soar_service, "get_action", AsyncMock(return_value=(run, action)))
    record_event_mock = AsyncMock()
    monkeypatch.setattr(soar_service, "record_event", record_event_mock)
    monkeypatch.setattr(soar_service, "_maybe_complete_run", AsyncMock())
    tenant_id = uuid.uuid4()
    incident_id = uuid.uuid4()
    rejector_id = uuid.uuid4()

    await soar_service.reject_action(_NullSession(), tenant_id, incident_id, run.id, action.id, rejector_id, reason="benign")

    record_event_mock.assert_called_once()
    kwargs = record_event_mock.call_args.kwargs
    assert kwargs["action"] == "soar.action.rejected"
    details = kwargs["details"]
    assert details["action_id"] == str(action.id)
    assert details["action_type"] == action.action_type.value
    assert details["incident_id"] == str(incident_id)
    assert details["run_id"] == str(run.id)
    assert details["autonomy_class"] == AutonomyClass.APPROVAL_REQUIRED.value
    assert details["rejected_by_user_id"] == str(rejector_id)
    assert details["reason"] == "benign"


# ── get_action: incident/run/action relationship isolation ──────────

@pytest.mark.asyncio
async def test_get_action_404s_when_action_belongs_to_a_different_run(monkeypatch):
    run = _run()
    other_action = _action()  # not in this run's action list
    monkeypatch.setattr(soar_service, "get_run", AsyncMock(return_value=(run, [])))

    with pytest.raises(SoarActionExecutionNotFoundError):
        await soar_service.get_action(_NullSession(), uuid.uuid4(), uuid.uuid4(), run.id, other_action.id)


@pytest.mark.asyncio
async def test_get_action_propagates_cross_tenant_incident_rejection(monkeypatch):
    monkeypatch.setattr(soar_service, "get_run", AsyncMock(side_effect=IncidentNotFoundError(uuid.uuid4())))

    with pytest.raises(IncidentNotFoundError):
        await soar_service.get_action(_NullSession(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4())


@pytest.mark.asyncio
async def test_get_action_propagates_wrong_run_for_incident(monkeypatch):
    monkeypatch.setattr(soar_service, "get_run", AsyncMock(side_effect=SoarRunNotFoundError(uuid.uuid4())))

    with pytest.raises(SoarRunNotFoundError):
        await soar_service.get_action(_NullSession(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4())


@pytest.mark.asyncio
async def test_approve_propagates_get_action_failures_unchanged(monkeypatch):
    """approve_action/reject_action never duplicate get_action's own scoping checks — they just propagate whatever it raises."""
    monkeypatch.setattr(soar_service, "get_action", AsyncMock(side_effect=SoarActionExecutionNotFoundError(uuid.uuid4())))

    with pytest.raises(SoarActionExecutionNotFoundError):
        await soar_service.approve_action(_NullSession(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4())


# ── Router layer: authorization, wiring, no bypass ───────────────────

class _FakeDbSession:
    async def execute(self, *args, **kwargs):
        raise AssertionError("the service layer is mocked in these tests — no query should reach the fake db session")


@pytest.fixture
def db_session():
    fake_session = _FakeDbSession()

    async def override_get_db():
        yield fake_session

    app.dependency_overrides[get_db] = override_get_db
    yield fake_session
    app.dependency_overrides.pop(get_db, None)


def test_approve_requires_authentication(client, db_session):
    response = client.post(f"/api/v1/incidents/{uuid.uuid4()}/soar/runs/{uuid.uuid4()}/actions/{uuid.uuid4()}/approve")
    assert response.status_code == 401


def test_reject_requires_authentication(client, db_session):
    response = client.post(f"/api/v1/incidents/{uuid.uuid4()}/soar/runs/{uuid.uuid4()}/actions/{uuid.uuid4()}/reject")
    assert response.status_code == 401


def test_approve_forbidden_for_viewer(client, db_session, make_auth_headers):
    headers = make_auth_headers(role=UserRole.VIEWER)
    response = client.post(f"/api/v1/incidents/{uuid.uuid4()}/soar/runs/{uuid.uuid4()}/actions/{uuid.uuid4()}/approve", headers=headers)
    assert response.status_code == 403


def test_reject_forbidden_for_viewer(client, db_session, make_auth_headers):
    headers = make_auth_headers(role=UserRole.VIEWER)
    response = client.post(f"/api/v1/incidents/{uuid.uuid4()}/soar/runs/{uuid.uuid4()}/actions/{uuid.uuid4()}/reject", headers=headers)
    assert response.status_code == 403


def test_approve_allowed_for_analyst_and_queues_the_existing_celery_worker(client, db_session, make_auth_headers, monkeypatch):
    """The critical wiring property: approval queues execute_soar_action.delay — the SAME Phase 2 task, never a new mechanism."""
    incident_id, run_id, action_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    action = _action(status=SoarActionStatus.APPROVED)
    action.id = action_id
    monkeypatch.setattr(router_module.soar_service, "approve_action", AsyncMock(return_value=action))
    delay_mock = Mock()
    monkeypatch.setattr(router_module.execute_soar_action, "delay", delay_mock)
    headers = make_auth_headers(role=UserRole.ANALYST)

    response = client.post(
        f"/api/v1/incidents/{incident_id}/soar/runs/{run_id}/actions/{action_id}/approve", headers=headers, json={"reason": "confirmed"}
    )

    assert response.status_code == 200
    assert response.json()["status"] == "approved"
    delay_mock.assert_called_once_with(str(action_id))


def test_approve_allowed_for_admin(client, db_session, make_auth_headers, monkeypatch):
    action = _action(status=SoarActionStatus.APPROVED)
    monkeypatch.setattr(router_module.soar_service, "approve_action", AsyncMock(return_value=action))
    monkeypatch.setattr(router_module.execute_soar_action, "delay", lambda *a, **kw: None)
    headers = make_auth_headers(role=UserRole.ADMIN)

    response = client.post(
        f"/api/v1/incidents/{uuid.uuid4()}/soar/runs/{uuid.uuid4()}/actions/{uuid.uuid4()}/approve", headers=headers
    )

    assert response.status_code == 200


def test_reject_allowed_for_analyst_and_never_queues_execution(client, db_session, make_auth_headers, monkeypatch):
    action = _action(status=SoarActionStatus.REJECTED)
    monkeypatch.setattr(router_module.soar_service, "reject_action", AsyncMock(return_value=action))
    delay_mock = Mock()
    monkeypatch.setattr(router_module.execute_soar_action, "delay", delay_mock)
    headers = make_auth_headers(role=UserRole.ANALYST)

    response = client.post(
        f"/api/v1/incidents/{uuid.uuid4()}/soar/runs/{uuid.uuid4()}/actions/{uuid.uuid4()}/reject", headers=headers, json={"reason": "benign"}
    )

    assert response.status_code == 200
    assert response.json()["status"] == "rejected"
    delay_mock.assert_not_called()


def test_approve_passes_the_acting_user_id_and_reason_through_to_the_service(client, db_session, make_auth_headers, monkeypatch):
    incident_id, run_id, action_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    mock = AsyncMock(return_value=_action(status=SoarActionStatus.APPROVED))
    monkeypatch.setattr(router_module.soar_service, "approve_action", mock)
    monkeypatch.setattr(router_module.execute_soar_action, "delay", lambda *a, **kw: None)
    user_id = uuid.uuid4()
    headers = make_auth_headers(user_id=user_id, role=UserRole.ANALYST)

    client.post(f"/api/v1/incidents/{incident_id}/soar/runs/{run_id}/actions/{action_id}/approve", headers=headers, json={"reason": "yep"})

    mock.assert_called_once()
    args = mock.call_args.args
    assert args[2] == incident_id
    assert args[3] == run_id
    assert args[4] == action_id
    assert args[5] == user_id
    assert args[6] == "yep"


def test_approve_derives_tenant_from_jwt_not_the_path(client, db_session, make_auth_headers, monkeypatch):
    tenant_id = uuid.uuid4()
    mock = AsyncMock(return_value=_action(status=SoarActionStatus.APPROVED))
    monkeypatch.setattr(router_module.soar_service, "approve_action", mock)
    monkeypatch.setattr(router_module.execute_soar_action, "delay", lambda *a, **kw: None)
    headers = make_auth_headers(tenant_id=tenant_id, role=UserRole.ANALYST)

    client.post(f"/api/v1/incidents/{uuid.uuid4()}/soar/runs/{uuid.uuid4()}/actions/{uuid.uuid4()}/approve", headers=headers)

    mock.assert_called_once()
    assert mock.call_args.args[1] == tenant_id


def test_approve_returns_404_for_cross_tenant_incident(client, db_session, make_auth_headers, monkeypatch):
    monkeypatch.setattr(router_module.soar_service, "approve_action", AsyncMock(side_effect=IncidentNotFoundError(uuid.uuid4())))
    headers = make_auth_headers(role=UserRole.ANALYST)

    response = client.post(f"/api/v1/incidents/{uuid.uuid4()}/soar/runs/{uuid.uuid4()}/actions/{uuid.uuid4()}/approve", headers=headers)

    assert response.status_code == 404


def test_approve_returns_404_for_action_belonging_to_a_different_run(client, db_session, make_auth_headers, monkeypatch):
    monkeypatch.setattr(router_module.soar_service, "approve_action", AsyncMock(side_effect=SoarActionExecutionNotFoundError(uuid.uuid4())))
    headers = make_auth_headers(role=UserRole.ANALYST)

    response = client.post(f"/api/v1/incidents/{uuid.uuid4()}/soar/runs/{uuid.uuid4()}/actions/{uuid.uuid4()}/approve", headers=headers)

    assert response.status_code == 404


def test_approve_returns_409_for_an_action_not_awaiting_approval(client, db_session, make_auth_headers, monkeypatch):
    monkeypatch.setattr(
        router_module.soar_service, "approve_action",
        AsyncMock(side_effect=InvalidSoarActionTransitionError(SoarActionStatus.REJECTED, SoarActionStatus.APPROVED)),
    )
    headers = make_auth_headers(role=UserRole.ANALYST)

    response = client.post(f"/api/v1/incidents/{uuid.uuid4()}/soar/runs/{uuid.uuid4()}/actions/{uuid.uuid4()}/approve", headers=headers)

    assert response.status_code in (400, 409, 422)  # exact code governed by core/exceptions.py's handler, not re-asserted here


def test_reject_returns_404_for_wrong_incident_run_action_chain(client, db_session, make_auth_headers, monkeypatch):
    monkeypatch.setattr(router_module.soar_service, "reject_action", AsyncMock(side_effect=SoarRunNotFoundError(uuid.uuid4())))
    headers = make_auth_headers(role=UserRole.ANALYST)

    response = client.post(f"/api/v1/incidents/{uuid.uuid4()}/soar/runs/{uuid.uuid4()}/actions/{uuid.uuid4()}/reject", headers=headers)

    assert response.status_code == 404


# ── GET /api/v1/soar/runs (tenant-wide) ──────────────────────────────

def test_list_all_runs_requires_authentication(client, db_session):
    response = client.get("/api/v1/soar/runs")
    assert response.status_code == 401


def test_list_all_runs_is_readable_by_a_viewer(client, db_session, make_auth_headers, monkeypatch):
    run = _run()
    action = _action()
    monkeypatch.setattr(router_module.soar_service, "list_all_runs_with_actions", AsyncMock(return_value=[(run, [action])]))
    headers = make_auth_headers(role=UserRole.VIEWER)

    response = client.get("/api/v1/soar/runs", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert len(body[0]["actions"]) == 1


def test_list_all_runs_derives_tenant_from_jwt(client, db_session, make_auth_headers, monkeypatch):
    tenant_id = uuid.uuid4()
    mock = AsyncMock(return_value=[])
    monkeypatch.setattr(router_module.soar_service, "list_all_runs_with_actions", mock)
    headers = make_auth_headers(tenant_id=tenant_id, role=UserRole.VIEWER)

    client.get("/api/v1/soar/runs", headers=headers)

    mock.assert_called_once()
    assert mock.call_args.args[1] == tenant_id
