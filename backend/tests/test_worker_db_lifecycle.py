"""
SafeSOC — Worker Database Lifecycle Tests (Phase 4.6)
Guards the fix for a confirmed production defect: Celery tasks run one
`asyncio.run()` per task, so every task gets a fresh event loop, while
the API's pooled engine kept asyncpg connections alive between tasks.
A connection handed to a later task wrote its `BEGIN` to a socket whose
transport belonged to a closed loop, then waited forever — stranding
the Postgres backend `idle in transaction` until the worker died, and
eventually exhausting `max_connections`.

The configuration assertions here are necessary but NOT sufficient, and
are deliberately not the whole story: the tests that actually matter
open real connections and prove that two sequential event loops never
share a backend. Those are skipped where no Postgres is reachable (the
local dev suite); they run inside the Docker suite, which has one.
"""

import asyncio

import pytest
from sqlalchemy import text
from sqlalchemy.pool import NullPool
from sqlalchemy.ext.asyncio import AsyncEngine

from app.db import postgresql
from app.db.postgresql import (
    async_session_factory,
    engine,
    worker_engine,
    worker_session_factory,
)


def _postgres_available() -> bool:
    async def _check() -> bool:
        try:
            async with worker_session_factory() as db:
                await db.execute(text("SELECT 1"))
            return True
        except Exception:
            return False

    try:
        return asyncio.run(_check())
    except Exception:
        return False


requires_postgres = pytest.mark.skipif(
    not _postgres_available(), reason="no reachable PostgreSQL (integration test)"
)


# ── Test 1 — worker factory configuration ───────────────────────────

def test_worker_engine_uses_nullpool():
    assert isinstance(worker_engine.pool, NullPool)


def test_api_engine_is_still_pooled_and_was_not_switched_to_nullpool():
    """
    The API runs on one long-lived event loop, where pooling is correct
    and valuable. The fix must not have quietly degraded it.
    """
    assert not isinstance(engine.pool, NullPool)
    assert type(engine.pool).__name__ == "AsyncAdaptedQueuePool"


def test_the_two_engines_and_factories_are_distinct():
    assert worker_engine is not engine
    assert worker_session_factory is not async_session_factory
    assert isinstance(worker_engine, AsyncEngine)


def test_both_engines_target_the_same_database():
    """One database, two pooling strategies — never a second URL."""
    assert worker_engine.url == engine.url


# ── Test 2 — sequential event loops (the real-world shape) ──────────

@requires_postgres
def test_repeated_event_loops_each_complete_successfully():
    """
    Ten tasks, ten event loops, exactly as Celery runs them. Before the
    fix the second and later iterations could receive a connection from
    a dead loop and hang on BEGIN.
    """
    async def one_task() -> int:
        async with worker_session_factory() as db:
            result = await db.execute(text("SELECT 1"))
            return result.scalar()

    for _ in range(10):
        assert asyncio.run(one_task()) == 1


@requires_postgres
def test_sequential_event_loops_leave_no_open_transaction_behind():
    async def one_task() -> None:
        async with worker_session_factory() as db:
            await db.execute(text("SELECT count(*) FROM incidents"))

    for _ in range(5):
        asyncio.run(one_task())

    async def count_stranded() -> int:
        async with worker_session_factory() as db:
            result = await db.execute(text(
                "SELECT count(*) FROM pg_stat_activity "
                "WHERE datname = current_database() AND state = 'idle in transaction' "
                "AND pid <> pg_backend_pid()"
            ))
            return result.scalar()

    assert asyncio.run(count_stranded()) == 0


# ── Test 3 — connection reuse is structurally impossible ────────────

@requires_postgres
def test_each_event_loop_gets_a_different_backend_connection():
    """
    Behaviour, not configuration: ask Postgres which backend served each
    task. NullPool must hand out a new one every time, because a reused
    backend is exactly the bug — a connection outliving the loop that
    opened it.
    """
    async def backend_pid() -> int:
        async with worker_session_factory() as db:
            result = await db.execute(text("SELECT pg_backend_pid()"))
            return result.scalar()

    pids = [asyncio.run(backend_pid()) for _ in range(6)]

    assert len(set(pids)) == len(pids), f"a backend was reused across event loops: {pids}"


@requires_postgres
def test_a_worker_connection_is_closed_when_its_session_closes():
    """The connection a task used must be gone afterwards, not parked in a pool."""
    async def use_and_report() -> int:
        async with worker_session_factory() as db:
            result = await db.execute(text("SELECT pg_backend_pid()"))
            return result.scalar()

    used_pid = asyncio.run(use_and_report())

    async def still_alive() -> bool:
        async with worker_session_factory() as db:
            result = await db.execute(
                text("SELECT count(*) FROM pg_stat_activity WHERE pid = :pid"), {"pid": used_pid}
            )
            return result.scalar() > 0

    assert asyncio.run(still_alive()) is False


# ── Test 4 — the API path is untouched ──────────────────────────────

@requires_postgres
def test_the_api_session_factory_still_works():
    """
    The pooled engine is disposed first on purpose. This test drives it
    from a brand-new event loop, which is exactly the situation its
    pool is NOT designed for — under FastAPI it only ever sees one
    long-lived loop. Without the dispose, an earlier test in the suite
    can leave a connection in the pool bound to a loop that is now
    closed, and this test would hang on the very defect this phase
    fixes for workers. Disposing first keeps the test about "does the
    API factory still function", not about pool/loop affinity.
    """
    async def api_style_request() -> int:
        await engine.dispose()
        try:
            async with async_session_factory() as db:
                result = await db.execute(text("SELECT 1"))
                return result.scalar()
        finally:
            await engine.dispose()

    assert asyncio.run(api_style_request()) == 1


def test_get_db_dependency_still_uses_the_pooled_api_factory():
    """FastAPI's dependency must not have been repointed at the worker engine."""
    import inspect

    source = inspect.getsource(postgresql.get_db)
    assert "async_session_factory" in source
    assert "worker_session_factory" not in source


# ── Tests 5 & 6 — the workers use the worker factory ────────────────

def test_every_celery_task_module_uses_the_worker_session_factory():
    """
    The defect was never SOAR-specific — it belonged to every task
    running under its own event loop. If a new task module starts using
    the API's pooled factory, this fails.
    """
    import inspect

    from app.tasks import enrichment, reporting, scoring
    from app.workers import correlation_worker, soar_worker

    for module in (soar_worker, correlation_worker, scoring, reporting, enrichment):
        source = inspect.getsource(module)
        assert "worker_session_factory" in source, f"{module.__name__} does not use the worker factory"
        assert "async_session_factory" not in source, f"{module.__name__} still uses the API factory"


def test_worker_modules_no_longer_dispose_the_shared_api_engine():
    """
    The dispose-before-and-after dance existed only to work around
    pooled connections outliving their loop. NullPool removes the
    reason; leaving the calls would also be disposing the API engine's
    pool from inside a worker process.
    """
    import inspect

    from app.tasks import reporting, scoring
    from app.workers import correlation_worker, soar_worker

    for module in (soar_worker, correlation_worker, scoring, reporting):
        assert "engine.dispose()" not in inspect.getsource(module), f"{module.__name__} still disposes an engine"


def test_correlation_worker_still_defers_soar_dispatch_until_after_its_session():
    """
    Unrelated to pooling and still load-bearing: queued actions are
    dispatched only after this task's session closes, so the child task
    cannot read rows the parent has not committed.
    """
    import inspect

    source = inspect.getsource(__import__("app.workers.correlation_worker", fromlist=["x"]))
    dispatch_index = source.index("execute_soar_action.delay")
    session_index = source.index("async with worker_session_factory()")
    assert dispatch_index > session_index
