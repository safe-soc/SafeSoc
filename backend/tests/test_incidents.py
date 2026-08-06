"""
SafeSOC — Incident Creation Service Tests
"""

import uuid
from datetime import datetime, timezone

import pytest

from app.core.enums import CorrelationPattern, IncidentStatus
from app.core.exceptions import IncidentNotFoundError, InvalidStateTransitionError
from app.models.incident import Incident, IncidentNote, IncidentStateTransition
from app.services.correlation import DetectedChain
from app.services.incidents import (
    add_note,
    create_incident,
    create_or_merge_incident,
    get_incident,
    link_alert,
    list_incidents,
    list_notes,
    transition_incident,
)


def _chain(*alert_ids, pattern=CorrelationPattern.CREDENTIAL_BRUTE_FORCE, confidence=0.8) -> DetectedChain:
    return DetectedChain(
        pattern=pattern,
        confidence=confidence,
        alert_ids=tuple(alert_ids),
        mitre_technique_ids=("T1110",),
        mitre_tactic="Credential Access",
    )


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)

    def scalar_one(self):
        return len(self._rows)

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None


class _FakeSession:
    """
    Fake AsyncSession tracking committed Incident rows so repeated calls
    within the same test can "see" incidents created by earlier calls,
    same as a real DB round-trip would.
    """

    def __init__(self, existing_incidents=None, existing_notes=None):
        self.existing_incidents: list[Incident] = list(existing_incidents or [])
        self.existing_notes: list[IncidentNote] = list(existing_notes or [])
        self.added: list = []
        self.all_added: list = []  # never cleared, for test inspection
        self.commit_count = 0
        self.execute_params: list = []  # never cleared, for test inspection

    async def execute(self, stmt, params=None):
        # Also receives the pg_advisory_xact_lock() call; this fake has no
        # real concurrency to serialize, so it's a no-op that still returns
        # a result shaped like the incidents/notes SELECT for the real
        # query. select(IncidentNote) is routed to existing_notes so
        # list_notes sees notes, not incidents, by inspecting what entity
        # the statement targets (a real query has no such ambiguity).
        self.execute_params.append(params)
        target = getattr(stmt, "column_descriptions", [{}])[0].get("type") if hasattr(stmt, "column_descriptions") else None
        if target is IncidentNote:
            return _FakeResult(self.existing_notes)
        return _FakeResult(self.existing_incidents)

    def add(self, obj):
        self.added.append(obj)
        self.all_added.append(obj)

    async def commit(self):
        self.commit_count += 1
        for obj in self.added:
            if isinstance(obj, Incident):
                if obj.id is None:
                    obj.id = uuid.uuid4()
                if obj not in self.existing_incidents:
                    self.existing_incidents.append(obj)
            elif isinstance(obj, IncidentNote):
                if obj.id is None:
                    obj.id = uuid.uuid4()
                if obj.created_at is None:
                    obj.created_at = datetime.now(timezone.utc)
                if obj not in self.existing_notes:
                    self.existing_notes.append(obj)
        self.added = []

    async def refresh(self, obj):
        pass


@pytest.mark.asyncio
async def test_acquires_a_tenant_and_host_scoped_advisory_lock_before_checking_for_a_match():
    """
    Guards against the race observed live: a batch of alerts for the same
    host spawns one Celery task per alert, and concurrent tasks running
    this check-then-create logic unlocked could both see "no active
    incident yet" and both create one. The lock call must happen, keyed
    on this tenant+host, before anything else.
    """
    session = _FakeSession()
    tenant_id = uuid.uuid4()

    await create_or_merge_incident(session, tenant_id, "HOST-1", _chain("a1"))

    assert session.execute_params[0] == {"lock_key": f"{tenant_id}:HOST-1"}


@pytest.mark.asyncio
async def test_creates_a_new_incident_when_none_exists():
    session = _FakeSession()
    tenant_id = uuid.uuid4()
    chain = _chain("a1", "a2", "a3")

    incident = await create_or_merge_incident(session, tenant_id, "HOST-1", chain)

    assert incident.tenant_id == tenant_id
    assert incident.status == IncidentStatus.OPEN
    assert set(incident.alert_ids) == {"a1", "a2", "a3"}
    assert session.commit_count >= 1


@pytest.mark.asyncio
async def test_creating_a_new_incident_records_the_initial_audit_transition():
    session = _FakeSession()
    tenant_id = uuid.uuid4()
    chain = _chain("a1")

    incident = await create_or_merge_incident(session, tenant_id, "HOST-1", chain)

    transitions = [obj for obj in session.all_added if isinstance(obj, IncidentStateTransition)]
    assert len(transitions) == 1
    assert transitions[0].incident_id == incident.id
    assert transitions[0].from_status is None
    assert transitions[0].to_status == IncidentStatus.OPEN
    assert transitions[0].changed_by_user_id is None  # system-generated, no human actor


@pytest.mark.asyncio
async def test_merging_into_an_existing_incident_does_not_record_a_new_transition():
    """Merging updates alert_ids only — status doesn't change, so no new transition."""
    tenant_id = uuid.uuid4()
    existing = Incident(id=uuid.uuid4(), tenant_id=tenant_id, status=IncidentStatus.OPEN, alert_ids=["a1"])
    session = _FakeSession(existing_incidents=[existing])

    await create_or_merge_incident(session, tenant_id, "HOST-1", _chain("a1", "a2"))

    transitions = [obj for obj in session.all_added if isinstance(obj, IncidentStateTransition)]
    assert transitions == []


@pytest.mark.asyncio
async def test_merges_into_an_existing_active_incident_with_overlapping_alerts():
    tenant_id = uuid.uuid4()
    existing = Incident(id=uuid.uuid4(), tenant_id=tenant_id, status=IncidentStatus.OPEN, alert_ids=["a1", "a2"])
    session = _FakeSession(existing_incidents=[existing])

    chain = _chain("a2", "a3", "a4")  # overlaps on a2
    incident = await create_or_merge_incident(session, tenant_id, "HOST-1", chain)

    assert incident.id == existing.id
    assert set(incident.alert_ids) == {"a1", "a2", "a3", "a4"}
    assert len(session.existing_incidents) == 1  # no new incident created


@pytest.mark.asyncio
async def test_does_not_merge_incidents_with_no_alert_overlap():
    tenant_id = uuid.uuid4()
    unrelated = Incident(id=uuid.uuid4(), tenant_id=tenant_id, status=IncidentStatus.OPEN, alert_ids=["x1", "x2"])
    session = _FakeSession(existing_incidents=[unrelated])

    chain = _chain("y1", "y2")
    incident = await create_or_merge_incident(session, tenant_id, "HOST-1", chain)

    assert incident.id != unrelated.id
    assert len(session.existing_incidents) == 2


# Note: create_or_merge_incident's tenant/active-status scoping happens in
# the SQL WHERE clause itself (select(...).where(Incident.tenant_id == ...,
# Incident.status.in_(_ACTIVE_STATUSES))) — a fake session that just hands
# back a canned Python list can't meaningfully prove a *different* tenant's
# or a *resolved* incident's row would actually be excluded by that clause,
# since it never evaluates real SQL. Those two properties are verified
# against live Postgres in Docker instead (see the issue's verification
# notes) rather than faked here in a way that would just be testing this
# test's own setup rather than the real query.


@pytest.mark.asyncio
async def test_repeated_detections_of_a_growing_chain_result_in_exactly_one_incident():
    """The real-world scenario: the same pattern re-fires as more alerts join the window."""
    session = _FakeSession()
    tenant_id = uuid.uuid4()

    await create_or_merge_incident(session, tenant_id, "HOST-1", _chain("a1", "a2", "a3", "a4", "a5"))
    await create_or_merge_incident(session, tenant_id, "HOST-1", _chain("a1", "a2", "a3", "a4", "a5", "a6"))
    final = await create_or_merge_incident(session, tenant_id, "HOST-1", _chain("a1", "a2", "a3", "a4", "a5", "a6", "a7"))

    assert len(session.existing_incidents) == 1
    assert set(final.alert_ids) == {"a1", "a2", "a3", "a4", "a5", "a6", "a7"}


# ── SS-036: manual creation, listing, retrieval, lifecycle transitions ──


@pytest.mark.asyncio
async def test_create_incident_opens_a_new_incident_with_the_given_alert_ids():
    session = _FakeSession()
    tenant_id = uuid.uuid4()

    incident = await create_incident(session, tenant_id, ["a1", "a2"])

    assert incident.tenant_id == tenant_id
    assert incident.status == IncidentStatus.OPEN
    assert incident.alert_ids == ["a1", "a2"]


@pytest.mark.asyncio
async def test_create_incident_defaults_to_no_alert_ids():
    session = _FakeSession()
    tenant_id = uuid.uuid4()

    incident = await create_incident(session, tenant_id)

    assert incident.alert_ids == []


@pytest.mark.asyncio
async def test_create_incident_records_the_initial_audit_transition():
    session = _FakeSession()
    tenant_id = uuid.uuid4()

    incident = await create_incident(session, tenant_id, ["a1"])

    transitions = [obj for obj in session.all_added if isinstance(obj, IncidentStateTransition)]
    assert len(transitions) == 1
    assert transitions[0].incident_id == incident.id
    assert transitions[0].from_status is None
    assert transitions[0].to_status == IncidentStatus.OPEN


@pytest.mark.asyncio
async def test_list_incidents_returns_matching_incidents_and_total_count():
    tenant_id = uuid.uuid4()
    existing = [
        Incident(id=uuid.uuid4(), tenant_id=tenant_id, status=IncidentStatus.OPEN, alert_ids=["a1"]),
        Incident(id=uuid.uuid4(), tenant_id=tenant_id, status=IncidentStatus.RESOLVED, alert_ids=["a2"]),
    ]
    session = _FakeSession(existing_incidents=existing)

    incidents, total = await list_incidents(session, tenant_id)

    assert total == 2
    assert len(incidents) == 2


# Note: as with create_or_merge_incident above, real tenant scoping and
# status filtering for list_incidents happen in the SQL WHERE clause
# itself — a fake session that hands back a canned list can't prove that
# clause actually excludes non-matching rows. Verified against live
# Postgres in Docker instead.


@pytest.mark.asyncio
async def test_get_incident_returns_the_incident_when_it_exists():
    tenant_id = uuid.uuid4()
    existing = Incident(id=uuid.uuid4(), tenant_id=tenant_id, status=IncidentStatus.OPEN, alert_ids=["a1"])
    session = _FakeSession(existing_incidents=[existing])

    incident = await get_incident(session, tenant_id, existing.id)

    assert incident.id == existing.id


@pytest.mark.asyncio
async def test_get_incident_raises_not_found_when_no_incident_exists():
    session = _FakeSession()
    tenant_id = uuid.uuid4()

    with pytest.raises(IncidentNotFoundError):
        await get_incident(session, tenant_id, uuid.uuid4())


@pytest.mark.asyncio
async def test_transition_allows_open_to_investigating():
    tenant_id = uuid.uuid4()
    existing = Incident(id=uuid.uuid4(), tenant_id=tenant_id, status=IncidentStatus.OPEN, alert_ids=["a1"])
    session = _FakeSession(existing_incidents=[existing])

    incident = await transition_incident(session, tenant_id, existing.id, IncidentStatus.INVESTIGATING)

    assert incident.status == IncidentStatus.INVESTIGATING


@pytest.mark.asyncio
async def test_transition_allows_investigating_to_resolved():
    tenant_id = uuid.uuid4()
    existing = Incident(id=uuid.uuid4(), tenant_id=tenant_id, status=IncidentStatus.INVESTIGATING, alert_ids=["a1"])
    session = _FakeSession(existing_incidents=[existing])

    incident = await transition_incident(session, tenant_id, existing.id, IncidentStatus.RESOLVED)

    assert incident.status == IncidentStatus.RESOLVED


@pytest.mark.asyncio
async def test_transition_allows_investigating_to_false_positive():
    tenant_id = uuid.uuid4()
    existing = Incident(id=uuid.uuid4(), tenant_id=tenant_id, status=IncidentStatus.INVESTIGATING, alert_ids=["a1"])
    session = _FakeSession(existing_incidents=[existing])

    incident = await transition_incident(session, tenant_id, existing.id, IncidentStatus.FALSE_POSITIVE)

    assert incident.status == IncidentStatus.FALSE_POSITIVE


@pytest.mark.asyncio
async def test_transition_rejects_resolved_to_open():
    """The AC's own example of a disallowed transition."""
    tenant_id = uuid.uuid4()
    existing = Incident(id=uuid.uuid4(), tenant_id=tenant_id, status=IncidentStatus.RESOLVED, alert_ids=["a1"])
    session = _FakeSession(existing_incidents=[existing])

    with pytest.raises(InvalidStateTransitionError):
        await transition_incident(session, tenant_id, existing.id, IncidentStatus.OPEN)

    assert existing.status == IncidentStatus.RESOLVED  # unchanged


@pytest.mark.asyncio
async def test_transition_rejects_skipping_investigating():
    tenant_id = uuid.uuid4()
    existing = Incident(id=uuid.uuid4(), tenant_id=tenant_id, status=IncidentStatus.OPEN, alert_ids=["a1"])
    session = _FakeSession(existing_incidents=[existing])

    with pytest.raises(InvalidStateTransitionError):
        await transition_incident(session, tenant_id, existing.id, IncidentStatus.RESOLVED)


@pytest.mark.asyncio
async def test_transition_rejects_moving_a_false_positive_incident_anywhere():
    tenant_id = uuid.uuid4()
    existing = Incident(id=uuid.uuid4(), tenant_id=tenant_id, status=IncidentStatus.FALSE_POSITIVE, alert_ids=["a1"])
    session = _FakeSession(existing_incidents=[existing])

    with pytest.raises(InvalidStateTransitionError):
        await transition_incident(session, tenant_id, existing.id, IncidentStatus.INVESTIGATING)


@pytest.mark.asyncio
async def test_transition_records_the_acting_user_on_the_audit_transition():
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    existing = Incident(id=uuid.uuid4(), tenant_id=tenant_id, status=IncidentStatus.OPEN, alert_ids=["a1"])
    session = _FakeSession(existing_incidents=[existing])

    await transition_incident(session, tenant_id, existing.id, IncidentStatus.INVESTIGATING, user_id)

    transitions = [obj for obj in session.all_added if isinstance(obj, IncidentStateTransition)]
    assert len(transitions) == 1
    assert transitions[0].from_status == IncidentStatus.OPEN
    assert transitions[0].to_status == IncidentStatus.INVESTIGATING
    assert transitions[0].changed_by_user_id == user_id


@pytest.mark.asyncio
async def test_transition_raises_not_found_for_a_missing_incident():
    session = _FakeSession()
    tenant_id = uuid.uuid4()

    with pytest.raises(IncidentNotFoundError):
        await transition_incident(session, tenant_id, uuid.uuid4(), IncidentStatus.INVESTIGATING)


# ── SS-037: post-creation alert linking + investigation notes ──


@pytest.mark.asyncio
async def test_link_alert_adds_a_new_alert_id():
    tenant_id = uuid.uuid4()
    existing = Incident(id=uuid.uuid4(), tenant_id=tenant_id, status=IncidentStatus.OPEN, alert_ids=["a1"])
    session = _FakeSession(existing_incidents=[existing])

    incident = await link_alert(session, tenant_id, existing.id, "a2")

    assert incident.alert_ids == ["a1", "a2"]


@pytest.mark.asyncio
async def test_link_alert_is_idempotent_when_already_linked():
    """The AC: linking an alert twice must not produce a duplicate entry."""
    tenant_id = uuid.uuid4()
    existing = Incident(id=uuid.uuid4(), tenant_id=tenant_id, status=IncidentStatus.OPEN, alert_ids=["a1", "a2"])
    session = _FakeSession(existing_incidents=[existing])

    incident = await link_alert(session, tenant_id, existing.id, "a2")

    assert incident.alert_ids == ["a1", "a2"]  # unchanged, not ["a1", "a2", "a2"]
    assert session.commit_count == 0  # no-op: nothing changed, nothing committed


@pytest.mark.asyncio
async def test_link_alert_raises_not_found_for_a_missing_incident():
    session = _FakeSession()
    tenant_id = uuid.uuid4()

    with pytest.raises(IncidentNotFoundError):
        await link_alert(session, tenant_id, uuid.uuid4(), "a1")


@pytest.mark.asyncio
async def test_add_note_creates_a_note_with_author_and_body():
    tenant_id = uuid.uuid4()
    author_id = uuid.uuid4()
    existing = Incident(id=uuid.uuid4(), tenant_id=tenant_id, status=IncidentStatus.OPEN, alert_ids=[])
    session = _FakeSession(existing_incidents=[existing])

    note = await add_note(session, tenant_id, existing.id, author_id, "Confirmed lateral movement.")

    assert note.incident_id == existing.id
    assert note.author_user_id == author_id
    assert note.body == "Confirmed lateral movement."
    assert note.created_at is not None


@pytest.mark.asyncio
async def test_add_note_raises_not_found_for_a_missing_incident():
    session = _FakeSession()
    tenant_id = uuid.uuid4()

    with pytest.raises(IncidentNotFoundError):
        await add_note(session, tenant_id, uuid.uuid4(), uuid.uuid4(), "unreachable")


@pytest.mark.asyncio
async def test_list_notes_returns_all_notes_for_the_incident():
    tenant_id = uuid.uuid4()
    incident_id = uuid.uuid4()
    existing = Incident(id=incident_id, tenant_id=tenant_id, status=IncidentStatus.OPEN, alert_ids=[])
    notes = [
        IncidentNote(id=uuid.uuid4(), incident_id=incident_id, author_user_id=uuid.uuid4(), body="First."),
        IncidentNote(id=uuid.uuid4(), incident_id=incident_id, author_user_id=uuid.uuid4(), body="Second."),
    ]
    session = _FakeSession(existing_incidents=[existing], existing_notes=notes)

    result = await list_notes(session, tenant_id, incident_id)

    assert len(result) == 2
    assert {note.body for note in result} == {"First.", "Second."}


@pytest.mark.asyncio
async def test_list_notes_raises_not_found_for_a_missing_incident():
    session = _FakeSession()
    tenant_id = uuid.uuid4()

    with pytest.raises(IncidentNotFoundError):
        await list_notes(session, tenant_id, uuid.uuid4())
