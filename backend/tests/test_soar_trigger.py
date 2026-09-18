"""
SafeSOC — SOAR Playbook Trigger Tests
match_playbook's deterministic selection (core/soar_playbooks.py) and
evaluate_triggers' idempotent run creation + automatic-action queuing
(services/soar.py, Phase 2 addition) — the integration point
workers/correlation_worker.py calls right after create_or_merge_incident.
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from app.core.enums import AutonomyClass, CorrelationPattern, RecommendationSource, SoarActionStatus, SoarActionType, SoarRunStatus, SoarTriggerSource, SoarVerificationStatus
from app.core.soar_playbooks import Playbook, PlaybookStep, PlaybookTrigger, match_playbook
from app.models.soar import SoarActionExecution, SoarPlaybookRun
from app.services import soar as soar_service


# ── match_playbook ───────────────────────────────────────────────────

def test_match_playbook_selects_the_correct_playbook_for_its_pattern():
    playbook = match_playbook(CorrelationPattern.SUCCESSFUL_COMPROMISE, confidence=0.9)
    assert playbook is not None
    assert playbook.id == "pb-successful-compromise"


def test_match_playbook_returns_none_when_confidence_is_below_threshold():
    playbook = match_playbook(CorrelationPattern.PRIVILEGE_ESCALATION, confidence=0.1)  # threshold is 0.7
    assert playbook is None


def test_match_playbook_returns_none_for_a_pattern_with_no_playbook(monkeypatch):
    monkeypatch.setattr("app.core.soar_playbooks.SOAR_PLAYBOOKS", [])
    assert match_playbook(CorrelationPattern.CREDENTIAL_BRUTE_FORCE, confidence=1.0) is None


def test_match_playbook_is_deterministic_across_multiple_matching_playbooks(monkeypatch):
    """Two playbooks both matching the same pattern: the higher min_confidence threshold wins, consistently."""
    lower = Playbook("pb-lower", "Lower", PlaybookTrigger(CorrelationPattern.LATERAL_MOVEMENT, 0.3), (PlaybookStep(SoarActionType.ADD_INCIDENT_NOTE),))
    higher = Playbook("pb-higher", "Higher", PlaybookTrigger(CorrelationPattern.LATERAL_MOVEMENT, 0.6), (PlaybookStep(SoarActionType.ADD_INCIDENT_NOTE),))
    monkeypatch.setattr("app.core.soar_playbooks.SOAR_PLAYBOOKS", [lower, higher])

    for _ in range(5):
        assert match_playbook(CorrelationPattern.LATERAL_MOVEMENT, confidence=0.8).id == "pb-higher"


def test_match_playbook_breaks_ties_by_playbook_id(monkeypatch):
    a = Playbook("pb-aaa", "A", PlaybookTrigger(CorrelationPattern.LATERAL_MOVEMENT, 0.5), (PlaybookStep(SoarActionType.ADD_INCIDENT_NOTE),))
    b = Playbook("pb-bbb", "B", PlaybookTrigger(CorrelationPattern.LATERAL_MOVEMENT, 0.5), (PlaybookStep(SoarActionType.ADD_INCIDENT_NOTE),))
    monkeypatch.setattr("app.core.soar_playbooks.SOAR_PLAYBOOKS", [b, a])  # deliberately out of order

    for _ in range(5):
        assert match_playbook(CorrelationPattern.LATERAL_MOVEMENT, confidence=0.9).id == "pb-aaa"


# ── evaluate_triggers ────────────────────────────────────────────────

class _FakeTriggerSession:
    """Only the query shapes evaluate_triggers itself issues (the advisory lock, the existing-run check, the created-actions fetch) — create_playbook_run is mocked, so it never touches this session."""

    def __init__(self, existing_run=None, actions=None):
        self.existing_run = existing_run
        self.actions = actions or []
        self.executed_raw = []

    async def execute(self, stmt, params=None):
        if params is not None and "lock_key" in params:
            self.executed_raw.append(params["lock_key"])
            return None
        target = getattr(stmt, "column_descriptions", [{}])[0].get("type") if hasattr(stmt, "column_descriptions") else None
        if target is SoarActionExecution:
            return _Result(self.actions)
        return _Result([self.existing_run] if self.existing_run else [])

    async def commit(self):
        pass


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None


def _run(playbook_id="pb-successful-compromise") -> SoarPlaybookRun:
    return SoarPlaybookRun(id=uuid.uuid4(), incident_id=uuid.uuid4(), playbook_id=playbook_id, triggered_by=SoarTriggerSource.AUTO_TRIGGER, status=SoarRunStatus.PENDING, created_at=datetime.now(timezone.utc))


def _mixed_actions(run_id) -> list[SoarActionExecution]:
    return [
        SoarActionExecution(id=uuid.uuid4(), playbook_run_id=run_id, action_type=SoarActionType.ENRICH_INDICATOR, parameters={}, autonomy_class=AutonomyClass.AUTOMATIC, recommended_by=RecommendationSource.PLAYBOOK_AUTO, status=SoarActionStatus.PENDING, verification_status=SoarVerificationStatus.NOT_VERIFIED),
        SoarActionExecution(id=uuid.uuid4(), playbook_run_id=run_id, action_type=SoarActionType.ISOLATE_ENDPOINT, parameters={}, autonomy_class=AutonomyClass.APPROVAL_REQUIRED, recommended_by=RecommendationSource.PLAYBOOK_AUTO, status=SoarActionStatus.PENDING, verification_status=SoarVerificationStatus.NOT_VERIFIED),
    ]


@pytest.mark.asyncio
async def test_evaluate_triggers_returns_none_when_no_playbook_matches(monkeypatch):
    monkeypatch.setattr("app.core.soar_playbooks.SOAR_PLAYBOOKS", [])
    db = _FakeTriggerSession()

    result = await soar_service.evaluate_triggers(db, uuid.uuid4(), uuid.uuid4(), CorrelationPattern.CREDENTIAL_BRUTE_FORCE, 0.9)

    assert result is None


@pytest.mark.asyncio
async def test_evaluate_triggers_creates_a_run_and_returns_only_automatic_action_ids(monkeypatch):
    tenant_id, incident_id = uuid.uuid4(), uuid.uuid4()
    run = _run()
    actions = _mixed_actions(run.id)
    db = _FakeTriggerSession(existing_run=None, actions=actions)

    monkeypatch.setattr(soar_service, "create_playbook_run", AsyncMock(return_value=run))
    monkeypatch.setattr(soar_service, "record_event", AsyncMock())

    result = await soar_service.evaluate_triggers(db, tenant_id, incident_id, CorrelationPattern.SUCCESSFUL_COMPROMISE, 0.9)

    assert result is not None
    returned_run, automatic_ids = result
    assert returned_run is run
    automatic_action = next(a for a in actions if a.autonomy_class == AutonomyClass.AUTOMATIC)
    approval_required_action = next(a for a in actions if a.autonomy_class == AutonomyClass.APPROVAL_REQUIRED)
    assert automatic_ids == [automatic_action.id]
    assert run.status == SoarRunStatus.RUNNING  # has at least one automatic action
    assert approval_required_action.status == SoarActionStatus.AWAITING_APPROVAL  # visible immediately, not left at PENDING


@pytest.mark.asyncio
async def test_evaluate_triggers_sets_run_to_awaiting_approval_when_no_automatic_actions(monkeypatch):
    tenant_id, incident_id = uuid.uuid4(), uuid.uuid4()
    run = _run()
    all_gated_action = SoarActionExecution(
        id=uuid.uuid4(), playbook_run_id=run.id, action_type=SoarActionType.ISOLATE_ENDPOINT, parameters={},
        autonomy_class=AutonomyClass.APPROVAL_REQUIRED, recommended_by=RecommendationSource.PLAYBOOK_AUTO,
        status=SoarActionStatus.PENDING, verification_status=SoarVerificationStatus.NOT_VERIFIED,
    )
    db = _FakeTriggerSession(existing_run=None, actions=[all_gated_action])
    monkeypatch.setattr(soar_service, "create_playbook_run", AsyncMock(return_value=run))
    monkeypatch.setattr(soar_service, "record_event", AsyncMock())

    result = await soar_service.evaluate_triggers(db, tenant_id, incident_id, CorrelationPattern.SUCCESSFUL_COMPROMISE, 0.9)

    returned_run, automatic_ids = result
    assert automatic_ids == []
    assert returned_run.status == SoarRunStatus.AWAITING_APPROVAL
    assert all_gated_action.status == SoarActionStatus.AWAITING_APPROVAL


@pytest.mark.asyncio
async def test_evaluate_triggers_does_not_create_a_duplicate_run_for_the_same_incident_and_playbook(monkeypatch):
    """The core idempotency guarantee: a run already exists for (incident, playbook) -> no second run, no queued actions."""
    tenant_id, incident_id = uuid.uuid4(), uuid.uuid4()
    existing_run = _run()
    db = _FakeTriggerSession(existing_run=existing_run)
    create_mock = AsyncMock()
    monkeypatch.setattr(soar_service, "create_playbook_run", create_mock)

    result = await soar_service.evaluate_triggers(db, tenant_id, incident_id, CorrelationPattern.SUCCESSFUL_COMPROMISE, 0.9)

    assert result is None
    create_mock.assert_not_called()


@pytest.mark.asyncio
async def test_evaluate_triggers_returns_none_for_a_pattern_below_every_playbooks_confidence_floor():
    db = _FakeTriggerSession()
    result = await soar_service.evaluate_triggers(db, uuid.uuid4(), uuid.uuid4(), CorrelationPattern.PRIVILEGE_ESCALATION, 0.01)
    assert result is None
