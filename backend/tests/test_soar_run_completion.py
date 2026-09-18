"""
SafeSOC — SOAR Run Completion Semantics Tests (Phase 3)
_maybe_complete_run (services/soar.py) decides what a playbook run
becomes once every one of its actions has reached a terminal state.
Phase 2 only ever had to handle RUNNING runs with SUCCEEDED/FAILED
actions; Phase 3 adds REJECTED as a second terminal action status and
AWAITING_APPROVAL as a second run status this function must resolve —
these tests pin down the exact resulting state for every combination,
including the three scenarios explicitly called out for this phase.

Semantics (see _maybe_complete_run's own docstring for the full
reasoning):
  RUNNING           -> FAILED    if any action FAILED
                    -> COMPLETED otherwise (REJECTED siblings don't fail a run)
  AWAITING_APPROVAL -> CANCELLED (only reachable if every action was REJECTED —
                                   anything ever approved would already have
                                   flipped the run to RUNNING)
  anything else     -> untouched
"""

import uuid
from datetime import datetime, timezone

import pytest

from app.core.enums import (
    AutonomyClass,
    RecommendationSource,
    SoarActionStatus,
    SoarRunStatus,
    SoarTriggerSource,
    SoarVerificationStatus,
)
from app.models.soar import SoarActionExecution, SoarPlaybookRun
from app.services import soar as soar_service


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)


class _FakeSession:
    """Serves _maybe_complete_run's one query (all actions for the run) and records whether commit() was called."""

    def __init__(self, actions):
        self.actions = actions
        self.commit_count = 0

    async def execute(self, stmt, params=None):
        return _Result(self.actions)

    async def commit(self):
        self.commit_count += 1


def _run(status: SoarRunStatus) -> SoarPlaybookRun:
    return SoarPlaybookRun(id=uuid.uuid4(), incident_id=uuid.uuid4(), playbook_id="pb-x", triggered_by=SoarTriggerSource.AUTO_TRIGGER, status=status)


def _action(status: SoarActionStatus, autonomy_class: AutonomyClass = AutonomyClass.AUTOMATIC) -> SoarActionExecution:
    from app.core.enums import SoarActionType
    return SoarActionExecution(
        id=uuid.uuid4(), playbook_run_id=uuid.uuid4(), action_type=SoarActionType.ADD_INCIDENT_NOTE,
        parameters={}, autonomy_class=autonomy_class, recommended_by=RecommendationSource.PLAYBOOK_AUTO,
        status=status, verification_status=SoarVerificationStatus.NOT_VERIFIED,
    )


# ── The three explicitly required scenarios ─────────────────────────

@pytest.mark.asyncio
async def test_automatic_succeed_plus_one_approved_succeeds_one_rejected_completes():
    """Automatic actions succeed + one approval-required action succeeds + another is rejected -> COMPLETED."""
    run = _run(SoarRunStatus.RUNNING)
    actions = [
        _action(SoarActionStatus.SUCCEEDED, AutonomyClass.AUTOMATIC),
        _action(SoarActionStatus.SUCCEEDED, AutonomyClass.AUTOMATIC),
        _action(SoarActionStatus.SUCCEEDED, AutonomyClass.APPROVAL_REQUIRED),  # was approved, executed, verified
        _action(SoarActionStatus.REJECTED, AutonomyClass.APPROVAL_REQUIRED),
    ]
    db = _FakeSession(actions)

    await soar_service._maybe_complete_run(db, run)

    assert run.status == SoarRunStatus.COMPLETED
    assert run.completed_at is not None
    assert db.commit_count == 1


@pytest.mark.asyncio
async def test_automatic_fails_plus_one_rejected_fails_the_run():
    """Automatic action fails + another approval-required action is rejected -> FAILED."""
    run = _run(SoarRunStatus.RUNNING)
    actions = [
        _action(SoarActionStatus.FAILED, AutonomyClass.AUTOMATIC),
        _action(SoarActionStatus.REJECTED, AutonomyClass.APPROVAL_REQUIRED),
    ]
    db = _FakeSession(actions)

    await soar_service._maybe_complete_run(db, run)

    assert run.status == SoarRunStatus.FAILED
    assert run.completed_at is not None


@pytest.mark.asyncio
async def test_all_approval_required_actions_rejected_cancels_the_run():
    """A run with zero AUTOMATIC actions, every one of which is rejected -> CANCELLED, never COMPLETED/FAILED."""
    run = _run(SoarRunStatus.AWAITING_APPROVAL)
    actions = [
        _action(SoarActionStatus.REJECTED, AutonomyClass.APPROVAL_REQUIRED),
        _action(SoarActionStatus.REJECTED, AutonomyClass.APPROVAL_REQUIRED),
    ]
    db = _FakeSession(actions)

    await soar_service._maybe_complete_run(db, run)

    assert run.status == SoarRunStatus.CANCELLED
    assert run.status not in (SoarRunStatus.COMPLETED, SoarRunStatus.FAILED)
    assert run.completed_at is not None


# ── General semantics: still in flight ───────────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize(
    "in_flight_status",
    [SoarActionStatus.PENDING, SoarActionStatus.AWAITING_APPROVAL, SoarActionStatus.APPROVED, SoarActionStatus.EXECUTING],
)
async def test_run_stays_open_while_any_action_is_not_yet_terminal(in_flight_status):
    run = _run(SoarRunStatus.RUNNING)
    actions = [_action(SoarActionStatus.SUCCEEDED, AutonomyClass.AUTOMATIC), _action(in_flight_status, AutonomyClass.APPROVAL_REQUIRED)]
    db = _FakeSession(actions)

    await soar_service._maybe_complete_run(db, run)

    assert run.status == SoarRunStatus.RUNNING  # untouched
    assert db.commit_count == 0


@pytest.mark.asyncio
async def test_approving_the_last_pending_action_does_not_complete_the_run_yet():
    """APPROVED is not itself terminal — the run stays open until the approved action actually finishes executing."""
    run = _run(SoarRunStatus.RUNNING)
    actions = [_action(SoarActionStatus.SUCCEEDED, AutonomyClass.AUTOMATIC), _action(SoarActionStatus.APPROVED, AutonomyClass.APPROVAL_REQUIRED)]
    db = _FakeSession(actions)

    await soar_service._maybe_complete_run(db, run)

    assert run.status == SoarRunStatus.RUNNING


# ── General semantics: only RUNNING/AWAITING_APPROVAL are candidates ─

@pytest.mark.asyncio
@pytest.mark.parametrize("terminal_status", [SoarRunStatus.COMPLETED, SoarRunStatus.FAILED, SoarRunStatus.CANCELLED, SoarRunStatus.PENDING])
async def test_run_already_settled_or_not_yet_started_is_left_untouched(terminal_status):
    run = _run(terminal_status)
    actions = [_action(SoarActionStatus.SUCCEEDED, AutonomyClass.AUTOMATIC)]
    db = _FakeSession(actions)

    await soar_service._maybe_complete_run(db, run)

    assert run.status == terminal_status  # never re-evaluated
    assert db.commit_count == 0


@pytest.mark.asyncio
async def test_all_succeeded_no_rejections_completes_normally():
    """Sanity check that Phase 2's original all-succeeded case is unaffected by the Phase 3 changes."""
    run = _run(SoarRunStatus.RUNNING)
    actions = [_action(SoarActionStatus.SUCCEEDED, AutonomyClass.AUTOMATIC), _action(SoarActionStatus.SUCCEEDED, AutonomyClass.AUTOMATIC)]
    db = _FakeSession(actions)

    await soar_service._maybe_complete_run(db, run)

    assert run.status == SoarRunStatus.COMPLETED


@pytest.mark.asyncio
async def test_calling_twice_is_idempotent():
    run = _run(SoarRunStatus.RUNNING)
    actions = [_action(SoarActionStatus.SUCCEEDED, AutonomyClass.AUTOMATIC)]
    db = _FakeSession(actions)

    await soar_service._maybe_complete_run(db, run)
    assert run.status == SoarRunStatus.COMPLETED
    first_completed_at = run.completed_at

    await soar_service._maybe_complete_run(db, run)  # run is now COMPLETED — second call is a no-op
    assert run.status == SoarRunStatus.COMPLETED
    assert run.completed_at == first_completed_at
    assert db.commit_count == 1  # only the first call actually committed anything
