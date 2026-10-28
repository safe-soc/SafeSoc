"""
SafeSOC — Incident Category Enum Migration Tests
e5f1a2b3c4d6 adds 'ransomware_precursor' to the incident_category
Postgres enum. Same structure as test_alert_dismiss_migration.py: the
chain and offline-SQL checks always run; a live round trip runs on a
throwaway database when a Postgres that allows CREATE DATABASE is
reachable, and is skipped otherwise.
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
from app.core.enums import CorrelationPattern

_BACKEND_DIR = Path(__file__).resolve().parent.parent
REVISION = "e5f1a2b3c4d6"
PREVIOUS = "d3a1c9e7f2b4"


def _config(output_buffer=None) -> Config:
    cfg = Config(output_buffer=output_buffer)
    cfg.set_main_option("script_location", str(_BACKEND_DIR / "migrations"))
    return cfg


def test_the_migration_is_the_single_head_on_top_of_the_dismiss_migration():
    script = ScriptDirectory.from_config(_config())

    assert script.get_heads() == [REVISION]
    assert script.get_revision(REVISION).down_revision == PREVIOUS


def _offline_sql(direction: str, revision_range: str) -> str:
    buffer = io.StringIO()
    getattr(command, direction)(_config(buffer), revision_range, sql=True)
    return buffer.getvalue()


def test_upgrade_adds_the_value_idempotently():
    sql = _offline_sql("upgrade", f"{PREVIOUS}:{REVISION}")

    assert "ALTER TYPE incident_category ADD VALUE IF NOT EXISTS 'ransomware_precursor'" in sql


def test_downgrade_is_a_no_op():
    sql = _offline_sql("downgrade", f"{REVISION}:{PREVIOUS}")

    assert "incident_category" not in sql


def test_the_migrations_create_every_correlation_pattern():
    """The original enum (378c96369721) plus every value added since must equal CorrelationPattern."""
    original = (_BACKEND_DIR / "migrations" / "versions" / "378c96369721_incident_category_and_confidence_ss_094.py").read_text()
    sql = _offline_sql("upgrade", f"{PREVIOUS}:{REVISION}")

    for pattern in CorrelationPattern:
        assert f"'{pattern.value}'" in original or f"'{pattern.value}'" in sql, pattern


# ── Live round trip on a throwaway database ──────────────────────────

async def _connect(database: str):
    import asyncpg

    return await asyncpg.connect(
        host=settings.POSTGRES_HOST, port=settings.POSTGRES_PORT, user=settings.POSTGRES_USER,
        password=settings.POSTGRES_PASSWORD, database=database, timeout=3,
    )


async def _admin(statement: str) -> None:
    conn = await _connect("postgres")
    try:
        await conn.execute(statement)
    finally:
        await conn.close()


async def _enum_values(database: str) -> list[str]:
    conn = await _connect(database)
    try:
        rows = await conn.fetch(
            "SELECT e.enumlabel FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid "
            "WHERE t.typname = 'incident_category' ORDER BY e.enumsortorder"
        )
        return [row["enumlabel"] for row in rows]
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
        assert set(asyncio.run(_enum_values(database))) == {p.value for p in CorrelationPattern}

        command.downgrade(cfg, PREVIOUS)  # documented no-op: the value stays
        assert "ransomware_precursor" in asyncio.run(_enum_values(database))

        command.upgrade(cfg, "head")  # IF NOT EXISTS: re-adding is harmless
        assert asyncio.run(_enum_values(database)).count("ransomware_precursor") == 1
    finally:
        asyncio.run(_admin(f'DROP DATABASE IF EXISTS "{database}" WITH (FORCE)'))
