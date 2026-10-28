"""
SafeSOC — Alert Dismiss-Reason Migration Tests
d3a1c9e7f2b4 adds alert_annotations.dismiss_reason/dismiss_note.

- Chain + offline-SQL tests always run (no database needed): the
  migration is the single head, and its upgrade/downgrade emit exactly
  the expected ADD/DROP COLUMN statements.
- A live up -> down -> up round trip runs against a throwaway database
  created on the reachable Postgres and dropped afterwards — never the
  real `safesoc` database. Skipped when no Postgres is reachable (CI).

The Alembic Config is built without a config file on purpose: env.py
only calls logging.config.fileConfig when there is one, and that would
reconfigure (and disable) the app's loggers for the rest of the suite.
"""

import asyncio
import io
import uuid
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory

from app.core.config import settings

_BACKEND_DIR = Path(__file__).resolve().parent.parent
REVISION = "d3a1c9e7f2b4"
PREVIOUS = "b4eb11fb1ac5"


def _config(output_buffer=None) -> Config:
    cfg = Config(output_buffer=output_buffer)
    cfg.set_main_option("script_location", str(_BACKEND_DIR / "migrations"))
    return cfg


def test_the_dismiss_migration_sits_on_soar_phase_3_below_a_single_head():
    script = ScriptDirectory.from_config(_config())

    [head] = script.get_heads()
    assert REVISION in {rev.revision for rev in script.iterate_revisions(head, "base")}
    assert script.get_revision(REVISION).down_revision == PREVIOUS


def _offline_sql(direction: str, revision_range: str) -> str:
    buffer = io.StringIO()
    getattr(command, direction)(_config(buffer), revision_range, sql=True)
    return buffer.getvalue()


def test_upgrade_adds_both_nullable_columns():
    sql = _offline_sql("upgrade", f"{PREVIOUS}:{REVISION}")

    assert "ALTER TABLE alert_annotations ADD COLUMN dismiss_reason VARCHAR(32)" in sql
    assert "ALTER TABLE alert_annotations ADD COLUMN dismiss_note VARCHAR(500)" in sql
    assert "NOT NULL" not in sql
    assert "CREATE TYPE" not in sql  # plain text, no Postgres enum type to clean up


def test_downgrade_drops_both_columns():
    sql = _offline_sql("downgrade", f"{REVISION}:{PREVIOUS}")

    assert "ALTER TABLE alert_annotations DROP COLUMN dismiss_note" in sql
    assert "ALTER TABLE alert_annotations DROP COLUMN dismiss_reason" in sql


# ── Live round trip on a throwaway database ──────────────────────────

async def _admin(statement: str) -> None:
    import asyncpg

    conn = await asyncpg.connect(
        host=settings.POSTGRES_HOST, port=settings.POSTGRES_PORT, user=settings.POSTGRES_USER,
        password=settings.POSTGRES_PASSWORD, database="postgres", timeout=3,
    )
    try:
        await conn.execute(statement)
    finally:
        await conn.close()


async def _columns(database: str) -> set[str]:
    import asyncpg

    conn = await asyncpg.connect(
        host=settings.POSTGRES_HOST, port=settings.POSTGRES_PORT, user=settings.POSTGRES_USER,
        password=settings.POSTGRES_PASSWORD, database=database, timeout=3,
    )
    try:
        rows = await conn.fetch(
            "SELECT column_name FROM information_schema.columns WHERE table_name = 'alert_annotations'"
        )
        return {row["column_name"] for row in rows}
    finally:
        await conn.close()


def _can_create_databases() -> bool:
    name = f"safesoc_probe_{uuid.uuid4().hex[:8]}"
    try:
        asyncio.run(_admin(f'CREATE DATABASE "{name}"'))
        asyncio.run(_admin(f'DROP DATABASE "{name}"'))
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _can_create_databases(), reason="no reachable PostgreSQL that allows CREATE DATABASE")
def test_live_upgrade_downgrade_upgrade_round_trip(monkeypatch):
    database = f"safesoc_migtest_{uuid.uuid4().hex[:8]}"
    asyncio.run(_admin(f'CREATE DATABASE "{database}"'))
    try:
        monkeypatch.setattr(settings, "POSTGRES_DB", database)
        cfg = _config()

        command.upgrade(cfg, "head")
        assert {"dismiss_reason", "dismiss_note"} <= asyncio.run(_columns(database))

        command.downgrade(cfg, PREVIOUS)
        columns = asyncio.run(_columns(database))
        assert "dismiss_reason" not in columns and "dismiss_note" not in columns
        assert {"acknowledged", "dismissed"} <= columns  # the rest of the table is untouched

        command.upgrade(cfg, "head")
        assert {"dismiss_reason", "dismiss_note"} <= asyncio.run(_columns(database))
    finally:
        asyncio.run(_admin(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)'))
