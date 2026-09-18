"""
SafeSOC — SOAR Worker Failure Semantics Tests (Phase 4.6)
The worker has to tell two failures apart, and the difference is not
cosmetic:

  * An APPLICATION failure is an outcome. services/soar_execution.py
    already recorded it — the action is FAILED, the audit event is
    written, the run is resolved. The task did its job; it returns
    normally.

  * An INFRASTRUCTURE failure is the absence of an outcome. The
    database was unreachable, so nothing was recorded anywhere. The
    task must fail loudly, or Celery reports success for work that
    never happened — which is exactly how a connection-exhaustion
    outage stayed invisible until a benchmark went looking for it.

Collapsing the two is the bug these tests exist to prevent.
"""

import uuid
from unittest.mock import AsyncMock

import pytest

from app.core.enums import SoarActionStatus, SoarActionType, SoarVerificationStatus
from app.tasks.celery_app import celery_app
from app.workers import soar_worker


class _FakeSessionCM:
    """Stands in for `async with worker_session_factory() as db`."""

    def __init__(self, on_enter=None):
        self._on_enter = on_enter
        self.exited = False

    async def __aenter__(self):
        if self._on_enter is not None:
            raise self._on_enter
        return "fake-db-session"

    async def __aexit__(self, *args):
        self.exited = True
        return False


def _action(status=SoarActionStatus.FAILED):
    action = AsyncMock()
    action.action_type = SoarActionType.ENRICH_INDICATOR
    action.status = status
    action.verification_status = SoarVerificationStatus.NOT_VERIFIED
    return action


def test_task_is_registered_with_celery():
    assert "app.workers.soar_worker.execute_soar_action" in celery_app.tasks


# ── Application failures stay quiet ─────────────────────────────────

@pytest.mark.asyncio
async def test_an_action_that_execute_action_marked_failed_does_not_raise(monkeypatch):
    """
    execute_action owns this outcome and has already recorded it. The
    task returning normally is correct — re-raising here would report a
    worker failure for a handled application result.
    """
    session = _FakeSessionCM()
    monkeypatch.setattr(soar_worker, "worker_session_factory", lambda: session)
    monkeypatch.setattr(
        soar_worker.soar_execution, "execute_action",
        AsyncMock(return_value=_action(SoarActionStatus.FAILED)),
    )

    await soar_worker._execute_soar_action_async(str(uuid.uuid4()))  # must not raise

    assert session.exited


@pytest.mark.asyncio
async def test_a_successful_action_does_not_raise(monkeypatch):
    session = _FakeSessionCM()
    monkeypatch.setattr(soar_worker, "worker_session_factory", lambda: session)
    monkeypatch.setattr(
        soar_worker.soar_execution, "execute_action",
        AsyncMock(return_value=_action(SoarActionStatus.SUCCEEDED)),
    )

    await soar_worker._execute_soar_action_async(str(uuid.uuid4()))

    assert session.exited


# ── Infrastructure failures propagate ───────────────────────────────

class _TooManyConnections(Exception):
    """Shaped like asyncpg's TooManyConnectionsError — the observed real failure."""


@pytest.mark.asyncio
async def test_a_database_failure_opening_the_session_propagates(monkeypatch):
    """The exact observed outage: connections exhausted before any work could start."""
    monkeypatch.setattr(
        soar_worker, "worker_session_factory",
        lambda: _FakeSessionCM(on_enter=_TooManyConnections("sorry, too many clients already")),
    )

    with pytest.raises(_TooManyConnections):
        await soar_worker._execute_soar_action_async(str(uuid.uuid4()))


@pytest.mark.asyncio
async def test_a_database_failure_during_execution_propagates(monkeypatch):
    session = _FakeSessionCM()
    monkeypatch.setattr(soar_worker, "worker_session_factory", lambda: session)
    monkeypatch.setattr(
        soar_worker.soar_execution, "execute_action",
        AsyncMock(side_effect=_TooManyConnections("sorry, too many clients already")),
    )

    with pytest.raises(_TooManyConnections):
        await soar_worker._execute_soar_action_async(str(uuid.uuid4()))

    assert session.exited, "the session must still be closed on the way out"


@pytest.mark.asyncio
async def test_the_failure_is_logged_with_context_before_being_re_raised(monkeypatch):
    """Re-raising is not a substitute for saying what happened."""
    monkeypatch.setattr(
        soar_worker, "worker_session_factory",
        lambda: _FakeSessionCM(on_enter=_TooManyConnections("boom")),
    )
    logged = {}

    def capture(message, **kwargs):
        logged["message"] = message
        logged.update(kwargs)

    monkeypatch.setattr(soar_worker.logger, "error", capture)
    action_id = str(uuid.uuid4())

    with pytest.raises(_TooManyConnections):
        await soar_worker._execute_soar_action_async(action_id)

    assert logged["action_id"] == action_id
    assert logged["error_type"] == "_TooManyConnections"


@pytest.mark.asyncio
async def test_an_unexpected_exception_is_not_swallowed(monkeypatch):
    """Anything unrecognised is treated as infrastructure, never as a quiet success."""
    session = _FakeSessionCM()
    monkeypatch.setattr(soar_worker, "worker_session_factory", lambda: session)
    monkeypatch.setattr(
        soar_worker.soar_execution, "execute_action", AsyncMock(side_effect=RuntimeError("unexpected")),
    )

    with pytest.raises(RuntimeError):
        await soar_worker._execute_soar_action_async(str(uuid.uuid4()))


# ── Re-raising must not have introduced retries ─────────────────────

def test_the_task_has_no_automatic_retry_behaviour():
    """
    Failing honestly is the point; retrying is a separate decision that
    was explicitly not made here. A retry policy appearing on this task
    would silently re-execute security-relevant actions.
    """
    task = celery_app.tasks["app.workers.soar_worker.execute_soar_action"]

    # Asserted against the registered task's own attributes rather than
    # the module text: the docstring names these settings in order to
    # explain that they are deliberately unset, and grepping source
    # would fail on the explanation instead of on the behaviour.
    assert not getattr(task, "autoretry_for", ()), "autoretry_for must stay empty"
    assert getattr(task, "retry_backoff", False) is False, "no retry backoff expected"
    assert task.acks_late is False, "acknowledgement behaviour must be unchanged"
    assert task.request.retries in (0, None), "the task must not be executing as a retry"
