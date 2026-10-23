"""
SafeSOC — Alert Triage Service Tests (SS-107)
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from app.core.enums import DismissReason, TriageStatus
from app.models.alert_annotation import AlertAnnotation
from app.services.alert_annotations import (
    acknowledge_alert,
    dismiss_alert,
    get_alert_ids_for_triage_status,
    get_annotations_for_alert_ids,
    restore_alert,
)


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None


class _FakeSession:
    def __init__(self, existing_annotations=None):
        self.existing_annotations: list[AlertAnnotation] = list(existing_annotations or [])
        self.added: list = []
        self.commit_count = 0

    async def execute(self, stmt, params=None):
        return _FakeResult(self.existing_annotations)

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        self.commit_count += 1
        for obj in self.added:
            if obj.id is None:
                obj.id = uuid.uuid4()
            if obj.updated_at is None:
                obj.updated_at = datetime.now(timezone.utc)
            if obj not in self.existing_annotations:
                self.existing_annotations.append(obj)
        self.added = []

    async def refresh(self, obj):
        pass


def _mock_record_event(monkeypatch):
    mock = AsyncMock()
    monkeypatch.setattr("app.services.alert_annotations.record_event", mock)
    return mock


# ── acknowledge_alert / dismiss_alert ────────────────────────────────

@pytest.mark.asyncio
async def test_acknowledge_creates_a_new_annotation(monkeypatch):
    _mock_record_event(monkeypatch)
    session = _FakeSession()
    tenant_id = uuid.uuid4()
    actor_id = uuid.uuid4()

    annotation = await acknowledge_alert(session, tenant_id, "alert-1", actor_id)

    assert annotation.tenant_id == tenant_id
    assert annotation.alert_id == "alert-1"
    assert annotation.acknowledged is True
    assert annotation.dismissed is False
    assert annotation.updated_by_user_id == actor_id


@pytest.mark.asyncio
async def test_dismiss_creates_a_new_annotation(monkeypatch):
    _mock_record_event(monkeypatch)
    session = _FakeSession()
    tenant_id = uuid.uuid4()
    actor_id = uuid.uuid4()

    annotation = await dismiss_alert(session, tenant_id, "alert-1", actor_id, reason=DismissReason.FALSE_POSITIVE)

    assert annotation.dismissed is True
    assert annotation.acknowledged is False


@pytest.mark.asyncio
async def test_acknowledge_and_dismiss_are_independent_flags(monkeypatch):
    """Acknowledging an alert must not also mark it dismissed, and vice versa — two separate flags, not a status enum."""
    _mock_record_event(monkeypatch)
    tenant_id = uuid.uuid4()
    actor_id = uuid.uuid4()
    session = _FakeSession()

    annotation = await acknowledge_alert(session, tenant_id, "alert-1", actor_id)
    annotation = await dismiss_alert(session, tenant_id, "alert-1", actor_id, reason=DismissReason.FALSE_POSITIVE)

    assert annotation.acknowledged is True
    assert annotation.dismissed is True
    assert len(session.existing_annotations) == 1  # upserted, not duplicated


@pytest.mark.asyncio
async def test_acknowledging_twice_updates_the_same_row(monkeypatch):
    _mock_record_event(monkeypatch)
    tenant_id = uuid.uuid4()
    first_actor = uuid.uuid4()
    second_actor = uuid.uuid4()
    session = _FakeSession()

    await acknowledge_alert(session, tenant_id, "alert-1", first_actor)
    annotation = await acknowledge_alert(session, tenant_id, "alert-1", second_actor)

    assert len(session.existing_annotations) == 1
    assert annotation.updated_by_user_id == second_actor


@pytest.mark.asyncio
async def test_acknowledge_records_an_audit_event(monkeypatch):
    mock_record = _mock_record_event(monkeypatch)
    session = _FakeSession()
    tenant_id = uuid.uuid4()
    actor_id = uuid.uuid4()

    await acknowledge_alert(session, tenant_id, "alert-1", actor_id)

    mock_record.assert_called_once_with(
        session, tenant_id, action="alert.acknowledged", target_type="alert", target_id="alert-1",
        actor_user_id=actor_id, details=None,
    )


@pytest.mark.asyncio
async def test_dismiss_records_an_audit_event(monkeypatch):
    mock_record = _mock_record_event(monkeypatch)
    session = _FakeSession()
    tenant_id = uuid.uuid4()
    actor_id = uuid.uuid4()

    await dismiss_alert(session, tenant_id, "alert-1", actor_id, reason=DismissReason.FALSE_POSITIVE)

    mock_record.assert_called_once_with(
        session, tenant_id, action="alert.dismissed", target_type="alert", target_id="alert-1",
        actor_user_id=actor_id, details={"reason": "false_positive", "note": None},
    )


@pytest.mark.asyncio
async def test_audit_failure_does_not_break_acknowledge(monkeypatch):
    monkeypatch.setattr(
        "app.services.alert_annotations.record_event", AsyncMock(side_effect=RuntimeError("db unavailable"))
    )
    session = _FakeSession()

    annotation = await acknowledge_alert(session, uuid.uuid4(), "alert-1", uuid.uuid4())  # must not raise

    assert annotation.acknowledged is True


@pytest.mark.asyncio
async def test_audit_failure_does_not_break_dismiss(monkeypatch):
    monkeypatch.setattr(
        "app.services.alert_annotations.record_event", AsyncMock(side_effect=RuntimeError("db unavailable"))
    )
    session = _FakeSession()

    annotation = await dismiss_alert(session, uuid.uuid4(), "alert-1", uuid.uuid4(), reason=DismissReason.DUPLICATE)  # must not raise

    assert annotation.dismissed is True


@pytest.mark.asyncio
async def test_dismiss_stores_the_reason_and_note(monkeypatch):
    _mock_record_event(monkeypatch)
    session = _FakeSession()

    annotation = await dismiss_alert(
        session, uuid.uuid4(), "alert-1", uuid.uuid4(), reason=DismissReason.OTHER, note="Pen-test window"
    )

    assert annotation.dismiss_reason == DismissReason.OTHER
    assert annotation.dismiss_note == "Pen-test window"


@pytest.mark.asyncio
async def test_dismiss_audit_details_record_the_reason_and_note(monkeypatch):
    mock_record = _mock_record_event(monkeypatch)
    session = _FakeSession()

    await dismiss_alert(
        session, uuid.uuid4(), "alert-1", uuid.uuid4(), reason=DismissReason.EXPECTED_ACTIVITY, note="Nightly backup"
    )

    assert mock_record.call_args.kwargs["details"] == {"reason": "expected_activity", "note": "Nightly backup"}


@pytest.mark.asyncio
async def test_restore_clears_dismissed_reason_and_note(monkeypatch):
    _mock_record_event(monkeypatch)
    tenant_id, actor_id = uuid.uuid4(), uuid.uuid4()
    session = _FakeSession()
    await acknowledge_alert(session, tenant_id, "alert-1", actor_id)
    await dismiss_alert(session, tenant_id, "alert-1", actor_id, reason=DismissReason.OTHER, note="Pen-test window")

    annotation = await restore_alert(session, tenant_id, "alert-1", actor_id)

    assert annotation.dismissed is False
    assert annotation.dismiss_reason is None
    assert annotation.dismiss_note is None
    assert annotation.acknowledged is True  # restore only undoes the dismissal
    assert len(session.existing_annotations) == 1


@pytest.mark.asyncio
async def test_restore_records_an_alert_restored_audit_event_with_what_was_cleared(monkeypatch):
    mock_record = _mock_record_event(monkeypatch)
    tenant_id, actor_id = uuid.uuid4(), uuid.uuid4()
    session = _FakeSession()
    await dismiss_alert(session, tenant_id, "alert-1", actor_id, reason=DismissReason.DUPLICATE, note="Same as a1")
    mock_record.reset_mock()

    await restore_alert(session, tenant_id, "alert-1", actor_id)

    mock_record.assert_called_once_with(
        session, tenant_id, action="alert.restored", target_type="alert", target_id="alert-1",
        actor_user_id=actor_id, details={"previous_reason": "duplicate", "previous_note": "Same as a1"},
    )


@pytest.mark.asyncio
async def test_audit_failure_does_not_break_restore(monkeypatch):
    monkeypatch.setattr(
        "app.services.alert_annotations.record_event", AsyncMock(side_effect=RuntimeError("db unavailable"))
    )
    session = _FakeSession()

    annotation = await restore_alert(session, uuid.uuid4(), "alert-1", uuid.uuid4())  # must not raise

    assert annotation.dismissed is False


# ── get_alert_ids_for_triage_status ──────────────────────────────────

class _IdsSession:
    """Returns fixed alert ids and keeps the statement so the WHERE clause can be inspected."""

    def __init__(self, ids):
        self._ids = ids
        self.statement = None

    async def execute(self, stmt, params=None):
        self.statement = stmt
        return _FakeResult(self._ids)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "triage, expected",
    [
        (TriageStatus.UNTRIAGED, (None, ["a1", "a2"])),
        (TriageStatus.ACKNOWLEDGED, (["a1", "a2"], None)),
        (TriageStatus.DISMISSED, (["a1", "a2"], None)),
    ],
)
async def test_triage_status_maps_to_include_or_exclude_ids(triage, expected):
    session = _IdsSession(["a1", "a2"])

    result = await get_alert_ids_for_triage_status(session, uuid.uuid4(), triage)

    assert result == expected


@pytest.mark.asyncio
async def test_triage_status_lookup_is_tenant_scoped():
    tenant_id = uuid.uuid4()
    session = _IdsSession([])

    await get_alert_ids_for_triage_status(session, tenant_id, TriageStatus.DISMISSED)

    compiled = session.statement.compile()
    assert "alert_annotations.tenant_id = :tenant_id_1" in str(compiled)
    assert compiled.params["tenant_id_1"] == tenant_id


# ── get_annotations_for_alert_ids ────────────────────────────────────

@pytest.mark.asyncio
async def test_get_annotations_for_alert_ids_returns_a_map_keyed_by_alert_id():
    tenant_id = uuid.uuid4()
    existing = [
        AlertAnnotation(id=uuid.uuid4(), tenant_id=tenant_id, alert_id="a1", acknowledged=True, dismissed=False, updated_by_user_id=uuid.uuid4()),
        AlertAnnotation(id=uuid.uuid4(), tenant_id=tenant_id, alert_id="a2", acknowledged=False, dismissed=True, updated_by_user_id=uuid.uuid4()),
    ]
    session = _FakeSession(existing_annotations=existing)

    result = await get_annotations_for_alert_ids(session, tenant_id, ["a1", "a2"])

    assert result["a1"].acknowledged is True
    assert result["a2"].dismissed is True


@pytest.mark.asyncio
async def test_get_annotations_for_alert_ids_returns_empty_for_empty_input():
    session = _FakeSession()

    result = await get_annotations_for_alert_ids(session, uuid.uuid4(), [])

    assert result == {}
