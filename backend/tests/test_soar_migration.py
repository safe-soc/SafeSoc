"""
SafeSOC — SOAR Migration Integrity Tests
Confirms exactly one new migration was added, chained from the prior
head with no branching, and that the ORM model's own metadata matches
the "no tenant_id, correct FKs" design — via Alembic's ScriptDirectory
and SQLAlchemy's table metadata, neither of which needs a live
database connection.
"""

from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory

from app.models.soar import SoarActionExecution, SoarPlaybookRun

_BACKEND_DIR = Path(__file__).resolve().parent.parent


def _script_directory() -> ScriptDirectory:
    cfg = Config(str(_BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(_BACKEND_DIR / "migrations"))
    return ScriptDirectory.from_config(cfg)


def test_there_is_exactly_one_migration_head():
    """No branching: the SOAR migration is the sole, linear successor of the prior head."""
    script = _script_directory()
    heads = script.get_heads()
    assert len(heads) == 1


def test_the_soar_migration_is_the_current_head_and_chains_from_the_prior_one():
    script = _script_directory()
    head_revision = script.get_revision(script.get_heads()[0])
    assert "soar" in (head_revision.doc or "").lower()
    # Exactly one down_revision — a real predecessor, not a fresh/branch root.
    assert head_revision.down_revision is not None


def test_exactly_two_migration_files_target_soar_tables():
    """
    One migration created the two SOAR tables (Phase 1); a second,
    later one (Phase 3) additively adds the approval-decision columns
    to soar_action_executions. Guards against a THIRD one sneaking in —
    i.e. the tables staying split across only these two, planned
    migrations, not an unbounded number.
    """
    soar_migrations = [
        path for path in (_BACKEND_DIR / "migrations" / "versions").glob("*.py")
        if "soar" in path.stem.lower()
    ]
    assert len(soar_migrations) == 2


# ── Model metadata matches the approved design ──────────────────────

def test_soar_playbook_run_has_no_tenant_id_column():
    assert "tenant_id" not in SoarPlaybookRun.__table__.columns


def test_soar_action_execution_has_no_tenant_id_column():
    assert "tenant_id" not in SoarActionExecution.__table__.columns


def test_soar_playbook_run_foreign_keys_target_incidents_only():
    targets = {fk.target_fullname for fk in SoarPlaybookRun.__table__.foreign_keys}
    assert targets == {"incidents.id"}


def test_soar_action_execution_foreign_keys_target_runs_and_users():
    targets = {fk.target_fullname for fk in SoarActionExecution.__table__.foreign_keys}
    assert targets == {"soar_playbook_runs.id", "users.id"}


def test_soar_action_execution_parameters_and_result_are_json_columns():
    from sqlalchemy import JSON

    assert isinstance(SoarActionExecution.__table__.columns["parameters"].type, JSON)
    assert isinstance(SoarActionExecution.__table__.columns["result"].type, JSON)


def test_soar_action_execution_approved_fields_are_nullable():
    """approved_by_user_id/approved_at must be nullable — most actions are never approved (AUTOMATIC ones don't need it, PENDING ones haven't reached it yet)."""
    assert SoarActionExecution.__table__.columns["approved_by_user_id"].nullable is True
    assert SoarActionExecution.__table__.columns["approved_at"].nullable is True


def test_soar_action_execution_rejected_fields_are_nullable():
    """rejected_by_user_id/rejected_at/decision_reason (Phase 3) must be nullable — an action is only ever approved OR rejected, never both."""
    assert SoarActionExecution.__table__.columns["rejected_by_user_id"].nullable is True
    assert SoarActionExecution.__table__.columns["rejected_at"].nullable is True
    assert SoarActionExecution.__table__.columns["decision_reason"].nullable is True


def test_soar_action_execution_parameters_column_is_not_nullable():
    """Every action has resolved+validated parameters at creation time — never null (empty dict for parameterless actions, never absent)."""
    assert SoarActionExecution.__table__.columns["parameters"].nullable is False
