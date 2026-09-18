"""
SafeSOC — SOAR Action Execution Worker
Celery entrypoint queued for every AUTOMATIC SoarActionExecution row
created by trigger evaluation (services/soar.py::evaluate_triggers,
called from workers/correlation_worker.py right after
create_or_merge_incident) and for every APPROVAL_REQUIRED action an
analyst has approved (routers/v1/soar.py) — never blocks the path that
queues it, same reasoning as notification_worker.py/
correlation_worker.py's own Celery tasks (ADR-005).

Two failure categories, deliberately kept apart:

  * APPLICATION failure — a handler or adapter refused, raised, or
    could not be verified. services/soar_execution.py::execute_action
    already owns that outcome: it transitions the action to FAILED,
    writes the audit event, and resolves the run. The task then returns
    normally, because nothing about the worker went wrong.

  * INFRASTRUCTURE failure — the database is unreachable, the session
    dies, connections are exhausted. execute_action cannot record
    anything, so the action stays where it was and the exception
    propagates out of this task. It is re-raised rather than swallowed:
    a task that could not do its work must not report success, or the
    failure is invisible to every operator looking at Celery.

Re-raising records the task as FAILURE and nothing more — there is no
autoretry_for, no self.retry(), no acks_late and no retry policy on
this app, so a failed action is not retried automatically. Recovering a
stranded action is a deliberate, separate concern.
"""

import asyncio
import uuid

from app.db.postgresql import worker_session_factory
from app.services import soar_execution
from app.tasks.celery_app import celery_app
from app.utils.logger import get_logger

logger = get_logger(__name__)


@celery_app.task(name="app.workers.soar_worker.execute_soar_action")
def execute_soar_action(action_id: str) -> None:
    """Celery entrypoint: execute one PENDING+AUTOMATIC or APPROVED SoarActionExecution by id."""
    asyncio.run(_execute_soar_action_async(action_id))


async def _execute_soar_action_async(action_id: str) -> None:
    # worker_session_factory (NullPool) — see db/postgresql.py. Every
    # Celery task runs under its own event loop, and a pooled asyncpg
    # connection cannot outlive the loop that opened it.
    try:
        async with worker_session_factory() as db:
            action = await soar_execution.execute_action(db, uuid.UUID(action_id))
            logger.info(
                "SOAR action execution finished", action_id=action_id,
                action_type=action.action_type.value, status=action.status.value,
                verification_status=action.verification_status.value,
            )
    except Exception as e:
        # Infrastructure failure: execute_action never got far enough to
        # record an outcome, so the action is left as it was and this
        # task has genuinely failed. No audit event is attempted here —
        # the failure is usually the database itself (connection
        # exhaustion is the observed case), and opening a second session
        # to report it would most likely fail too and add load to an
        # already-struggling instance. The structured log is the honest
        # record; the re-raise is what makes Celery agree.
        logger.error(
            "SOAR action execution failed", action_id=action_id,
            error_type=type(e).__name__, error=str(e),
        )
        raise
