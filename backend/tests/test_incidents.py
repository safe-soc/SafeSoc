"""
SafeSOC — Incident Creation Service Tests
"""

import uuid

import pytest

from app.core.enums import CorrelationPattern, IncidentStatus
from app.models.incident import Incident, IncidentStateTransition
from app.services.correlation import DetectedChain
from app.services.incidents import create_or_merge_incident


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


class _FakeSession:
    """
    Fake AsyncSession tracking committed Incident rows so repeated calls
    within the same test can "see" incidents created by earlier calls,
    same as a real DB round-trip would.
    """

    def __init__(self, existing_incidents=None):
        self.existing_incidents: list[Incident] = list(existing_incidents or [])
        self.added: list = []
        self.all_added: list = []  # never cleared, for test inspection
        self.commit_count = 0
        self.execute_params: list = []  # never cleared, for test inspection

    async def execute(self, stmt, params=None):
        # Also receives the pg_advisory_xact_lock() call; this fake has no
        # real concurrency to serialize, so it's a no-op that still returns
        # a result shaped like the incidents SELECT for the real query.
        self.execute_params.append(params)
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
