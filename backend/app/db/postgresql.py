"""
SafeSOC — PostgreSQL Client
Async engine, session factory, and connectivity check.

Two engines, because the API and the Celery workers have fundamentally
different event-loop lifetimes:

  * `engine` / `async_session_factory` — the API path. FastAPI serves
    every request on one long-lived event loop, so a pooled connection
    is always reused under the loop that created it. Pooling is the
    right choice there and is unchanged.

  * `worker_engine` / `worker_session_factory` — the Celery path. Each
    task runs `asyncio.run(...)`, which creates a NEW event loop and
    closes it when the task returns. An asyncpg connection belongs to
    the loop that opened it: its transport and protocol live on that
    loop. A pooled connection handed to a later task therefore writes
    its `BEGIN` to the socket and then waits forever for a reply
    nothing will ever read, stranding the backend `idle in transaction`
    until the worker process dies. NullPool makes that structurally
    impossible — every task opens its own connection and closes it on
    session exit, so nothing survives the loop that created it.

The worker engine is not a tuning preference; it is a correctness
requirement of running async SQLAlchemy under one event loop per task.
Measured before the split: idle-in-transaction connections accumulated
monotonically across task bursts until Postgres refused new clients
with "sorry, too many clients already".
"""

from collections.abc import AsyncGenerator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import settings

engine = create_async_engine(settings.postgres_url, pool_pre_ping=True)

async_session_factory = async_sessionmaker(engine, expire_on_commit=False)

# Same database, same settings — only the pooling strategy differs.
# NullPool holds no connection open between checkouts, so a Celery task
# can never inherit one from a previous task's event loop. This also
# removes the need for the per-task `engine.dispose()` calls the worker
# modules used to make: there is no pool left to dispose.
worker_engine = create_async_engine(settings.postgres_url, poolclass=NullPool)

worker_session_factory = async_sessionmaker(worker_engine, expire_on_commit=False)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency yielding a request-scoped async session."""
    async with async_session_factory() as session:
        yield session


async def check_connection() -> bool:
    """Check if PostgreSQL is reachable. Returns True if healthy."""
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
