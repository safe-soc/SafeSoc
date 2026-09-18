"""
SafeSOC — SOAR Service Tests
State machine (valid/invalid transitions, including the autonomy-
gated PENDING -> EXECUTING guard), playbook-run creation (tenant
scoping, unknown playbook, atomic parameter-validation failure), and
read-path tenant/incident-relationship isolation — the boundary-mocked
approach test_compliance.py/test_threat_analytics.py already establish
for this codebase (a raw fake session can't meaningfully prove real
tenant-scoped SQL filtering; that's verified live via Docker, same
reasoning those files give).
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from app.core.enums import (
    AutonomyClass,
    IncidentStatus,
    RecommendationSource,
    SoarActionStatus,
    SoarActionType,
    SoarRunStatus,
    SoarTriggerSource,
    SoarVerificationStatus,
)
from app.core.exceptions import (
    IncidentNotFoundError,
    InvalidSoarActionTransitionError,
    InvalidSoarRunTransitionError,
    SoarActionParameterError,
    SoarPlaybookNotFoundError,
    SoarRunNotFoundError,
)
from app.models.incident import Incident
from app.models.soar import SoarActionExecution, SoarPlaybookRun
from app.services import soar as soar_service
from app.services.incident_evidence import HostEntity, IncidentEvidence, IPEntity, UserEntity


def _action(status=SoarActionStatus.PENDING, autonomy_class=AutonomyClass.AUTOMATIC) -> SoarActionExecution:
    return SoarActionExecution(
        id=uuid.uuid4(), playbook_run_id=uuid.uuid4(), action_type=SoarActionType.ADD_INCIDENT_NOTE,
        parameters={"note": "x"}, autonomy_class=autonomy_class, recommended_by=RecommendationSource.PLAYBOOK_AUTO,
        status=status, verification_status=SoarVerificationStatus.NOT_VERIFIED,
    )


def _run(status=SoarRunStatus.PENDING) -> SoarPlaybookRun:
    return SoarPlaybookRun(id=uuid.uuid4(), incident_id=uuid.uuid4(), playbook_id="pb-x", triggered_by=SoarTriggerSource.MANUAL, status=status)


# ── Run-level state machine ─────────────────────────────────────────

@pytest.mark.parametrize(
    "from_status,to_status",
    [
        (SoarRunStatus.PENDING, SoarRunStatus.RUNNING),
        (SoarRunStatus.PENDING, SoarRunStatus.AWAITING_APPROVAL),
        (SoarRunStatus.PENDING, SoarRunStatus.CANCELLED),
        (SoarRunStatus.AWAITING_APPROVAL, SoarRunStatus.RUNNING),
        (SoarRunStatus.AWAITING_APPROVAL, SoarRunStatus.CANCELLED),
        (SoarRunStatus.RUNNING, SoarRunStatus.COMPLETED),
        (SoarRunStatus.RUNNING, SoarRunStatus.FAILED),
    ],
)
def test_valid_run_transitions(from_status, to_status):
    run = _run(status=from_status)
    soar_service.transition_run_status(run, to_status)
    assert run.status == to_status


@pytest.mark.parametrize(
    "from_status,to_status",
    [
        (SoarRunStatus.COMPLETED, SoarRunStatus.RUNNING),
        (SoarRunStatus.FAILED, SoarRunStatus.RUNNING),
        (SoarRunStatus.CANCELLED, SoarRunStatus.RUNNING),
        (SoarRunStatus.PENDING, SoarRunStatus.COMPLETED),  # can't skip straight to completed
        (SoarRunStatus.RUNNING, SoarRunStatus.PENDING),  # no going backward
    ],
)
def test_invalid_run_transitions_raise(from_status, to_status):
    run = _run(status=from_status)
    with pytest.raises(InvalidSoarRunTransitionError):
        soar_service.transition_run_status(run, to_status)
    assert run.status == from_status  # unchanged on rejection


# ── Action-level state machine ──────────────────────────────────────

def test_pending_to_executing_is_valid_for_an_automatic_action():
    action = _action(status=SoarActionStatus.PENDING, autonomy_class=AutonomyClass.AUTOMATIC)
    soar_service.transition_action_status(action, SoarActionStatus.EXECUTING)
    assert action.status == SoarActionStatus.EXECUTING


def test_pending_to_executing_is_rejected_for_an_approval_required_action():
    """The core safety guarantee: approval cannot be skipped even though PENDING->EXECUTING is graph-reachable."""
    action = _action(status=SoarActionStatus.PENDING, autonomy_class=AutonomyClass.APPROVAL_REQUIRED)
    with pytest.raises(InvalidSoarActionTransitionError):
        soar_service.transition_action_status(action, SoarActionStatus.EXECUTING)
    assert action.status == SoarActionStatus.PENDING


@pytest.mark.parametrize(
    "from_status,to_status",
    [
        (SoarActionStatus.PENDING, SoarActionStatus.AWAITING_APPROVAL),
        (SoarActionStatus.AWAITING_APPROVAL, SoarActionStatus.APPROVED),
        (SoarActionStatus.AWAITING_APPROVAL, SoarActionStatus.REJECTED),
        (SoarActionStatus.APPROVED, SoarActionStatus.EXECUTING),
        (SoarActionStatus.EXECUTING, SoarActionStatus.SUCCEEDED),
        (SoarActionStatus.EXECUTING, SoarActionStatus.FAILED),
    ],
)
def test_valid_action_transitions(from_status, to_status):
    action = _action(status=from_status, autonomy_class=AutonomyClass.APPROVAL_REQUIRED)
    soar_service.transition_action_status(action, to_status)
    assert action.status == to_status


@pytest.mark.parametrize(
    "from_status,to_status",
    [
        (SoarActionStatus.REJECTED, SoarActionStatus.EXECUTING),
        (SoarActionStatus.SUCCEEDED, SoarActionStatus.EXECUTING),
        (SoarActionStatus.FAILED, SoarActionStatus.EXECUTING),  # no retry transition exists yet, by design
        (SoarActionStatus.PENDING, SoarActionStatus.APPROVED),  # can't skip AWAITING_APPROVAL
        (SoarActionStatus.PENDING, SoarActionStatus.SUCCEEDED),
        (SoarActionStatus.APPROVED, SoarActionStatus.REJECTED),  # already past the reject point
    ],
)
def test_invalid_action_transitions_raise(from_status, to_status):
    action = _action(status=from_status, autonomy_class=AutonomyClass.APPROVAL_REQUIRED)
    with pytest.raises(InvalidSoarActionTransitionError):
        soar_service.transition_action_status(action, to_status)
    assert action.status == from_status


def test_client_cannot_select_an_arbitrary_status_string():
    """to_status is typed SoarActionStatus — an out-of-enum value can't even be constructed to pass in."""
    with pytest.raises(ValueError):
        SoarActionStatus("not_a_real_status")


# ── create_playbook_run ──────────────────────────────────────────────

class _FakeSoarSession:
    """Add/flush/commit assign id/created_at the way a real DB round-trip would (mirrors test_incidents_router.py's own fake-session convention)."""

    def __init__(self):
        self.added: list = []
        self.committed: list = []

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        for obj in self.added:
            if getattr(obj, "id", None) is None:
                obj.id = uuid.uuid4()

    async def commit(self):
        await self.flush()
        now = datetime.now(timezone.utc)
        for obj in self.added:
            if getattr(obj, "created_at", None) is None:
                obj.created_at = now
        self.committed.extend(self.added)
        self.added = []

    async def refresh(self, obj):
        pass

    async def execute(self, *args, **kwargs):
        raise AssertionError("create_playbook_run should reach the DB only via get_incident/get_incident_evidence — both mocked in these tests")


def _incident(tenant_id, incident_id=None) -> Incident:
    return Incident(
        id=incident_id or uuid.uuid4(), tenant_id=tenant_id, status=IncidentStatus.OPEN,
        alert_ids=[], category=None, confidence=None, tags=[], created_at=datetime.now(timezone.utc),
    )


def _evidence(incident_id, hosts=(), ips=(), users=()) -> IncidentEvidence:
    return IncidentEvidence(
        incident_id=incident_id,
        hosts=[HostEntity(host_id=h, alert_count=1) for h in hosts],
        ips=[IPEntity(ip=i, roles=["source"], alert_count=1) for i in ips],
        users=[UserEntity(user=u, alert_count=1) for u in users],
        cloud_resources=[],
    )


@pytest.mark.asyncio
async def test_create_playbook_run_creates_run_and_actions(monkeypatch):
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id)
    monkeypatch.setattr(soar_service, "get_incident", AsyncMock(return_value=incident))
    monkeypatch.setattr(soar_service, "get_incident_evidence", AsyncMock(return_value=_evidence(incident.id, hosts=["DESKTOP-042"], ips=["203.0.113.5"])))
    monkeypatch.setattr(soar_service, "record_event", AsyncMock())
    db = _FakeSoarSession()

    run = await soar_service.create_playbook_run(db, tenant_id, incident.id, "pb-successful-compromise")

    assert run.incident_id == incident.id
    assert run.status == SoarRunStatus.PENDING
    created_actions = [obj for obj in db.committed if isinstance(obj, SoarActionExecution)]
    assert len(created_actions) == 4  # pb-successful-compromise has 4 steps
    assert all(action.playbook_run_id == run.id for action in created_actions)
    assert all(action.status == SoarActionStatus.PENDING for action in created_actions)
    isolate_action = next(a for a in created_actions if a.action_type == SoarActionType.ISOLATE_ENDPOINT)
    assert isolate_action.autonomy_class == AutonomyClass.APPROVAL_REQUIRED
    assert isolate_action.parameters == {"host_id": "DESKTOP-042"}


@pytest.mark.asyncio
async def test_create_playbook_run_snapshots_autonomy_class_from_policy_at_creation_time(monkeypatch):
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id)
    monkeypatch.setattr(soar_service, "get_incident", AsyncMock(return_value=incident))
    monkeypatch.setattr(soar_service, "get_incident_evidence", AsyncMock(return_value=_evidence(incident.id, ips=["203.0.113.5"])))
    monkeypatch.setattr(soar_service, "record_event", AsyncMock())
    db = _FakeSoarSession()

    run = await soar_service.create_playbook_run(db, tenant_id, incident.id, "pb-credential-brute-force")

    actions = [obj for obj in db.committed if isinstance(obj, SoarActionExecution)]
    enrich_action = next(a for a in actions if a.action_type == SoarActionType.ENRICH_INDICATOR)
    assert enrich_action.autonomy_class == AutonomyClass.AUTOMATIC
    assert run.status == SoarRunStatus.PENDING


@pytest.mark.asyncio
async def test_create_playbook_run_raises_for_unknown_playbook(monkeypatch):
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id)
    monkeypatch.setattr(soar_service, "get_incident", AsyncMock(return_value=incident))
    db = _FakeSoarSession()

    with pytest.raises(SoarPlaybookNotFoundError):
        await soar_service.create_playbook_run(db, tenant_id, incident.id, "not-a-real-playbook")
    assert db.committed == []  # nothing created


@pytest.mark.asyncio
async def test_create_playbook_run_propagates_incident_not_found(monkeypatch):
    monkeypatch.setattr(soar_service, "get_incident", AsyncMock(side_effect=IncidentNotFoundError(uuid.uuid4())))
    db = _FakeSoarSession()

    with pytest.raises(IncidentNotFoundError):
        await soar_service.create_playbook_run(db, uuid.uuid4(), uuid.uuid4(), "pb-successful-compromise")
    assert db.committed == []


@pytest.mark.asyncio
async def test_create_playbook_run_skips_steps_whose_evidence_is_unavailable(monkeypatch):
    """
    Phase 3.5: an incident with NO host/ip/user evidence at all still
    produces a run — the three evidence-dependent steps of
    pb-successful-compromise are skipped, the one static step
    (ADD_INCIDENT_NOTE) still runs. Before 3.5 this raised
    SoarActionParameterError and took the whole correlation task down
    with it.
    """
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id)
    monkeypatch.setattr(soar_service, "get_incident", AsyncMock(return_value=incident))
    monkeypatch.setattr(soar_service, "get_incident_evidence", AsyncMock(return_value=_evidence(incident.id)))  # no hosts/ips/users at all
    monkeypatch.setattr(soar_service, "record_event", AsyncMock())
    db = _FakeSoarSession()

    run = await soar_service.create_playbook_run(db, tenant_id, incident.id, "pb-successful-compromise")

    created_actions = [obj for obj in db.committed if isinstance(obj, SoarActionExecution)]
    assert [a.action_type for a in created_actions] == [SoarActionType.ADD_INCIDENT_NOTE]
    assert run.incident_id == incident.id


# ── Reads: tenant + incident/run relationship isolation ─────────────

class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None


class _FakeReadSession:
    def __init__(self, runs=None, actions=None):
        self.runs = list(runs or [])
        self.actions = list(actions or [])

    async def execute(self, stmt, params=None):
        target = getattr(stmt, "column_descriptions", [{}])[0].get("type") if hasattr(stmt, "column_descriptions") else None
        if target is SoarActionExecution:
            return _FakeResult(self.actions)
        return _FakeResult(self.runs)


@pytest.mark.asyncio
async def test_list_runs_only_returns_this_incidents_runs(monkeypatch):
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id)
    monkeypatch.setattr(soar_service, "get_incident", AsyncMock(return_value=incident))
    own_run = SoarPlaybookRun(id=uuid.uuid4(), incident_id=incident.id, playbook_id="pb-x", triggered_by=SoarTriggerSource.MANUAL, status=SoarRunStatus.PENDING, created_at=datetime.now(timezone.utc))
    db = _FakeReadSession(runs=[own_run])

    runs = await soar_service.list_runs(db, tenant_id, incident.id)

    assert runs == [own_run]


@pytest.mark.asyncio
async def test_list_runs_propagates_incident_not_found_for_cross_tenant_incident(monkeypatch):
    monkeypatch.setattr(soar_service, "get_incident", AsyncMock(side_effect=IncidentNotFoundError(uuid.uuid4())))
    db = _FakeReadSession()

    with pytest.raises(IncidentNotFoundError):
        await soar_service.list_runs(db, uuid.uuid4(), uuid.uuid4())


@pytest.mark.asyncio
async def test_get_run_rejects_a_run_belonging_to_a_different_incident(monkeypatch):
    """
    The critical isolation property: a real run_id that exists, but
    under a DIFFERENT incident than the one in the URL, must 404 —
    never resolve just because the id itself is valid.
    """
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id)
    monkeypatch.setattr(soar_service, "get_incident", AsyncMock(return_value=incident))
    db = _FakeReadSession(runs=[])  # the fake session's query correctly finds nothing for THIS incident

    with pytest.raises(SoarRunNotFoundError):
        await soar_service.get_run(db, tenant_id, incident.id, uuid.uuid4())


@pytest.mark.asyncio
async def test_get_run_returns_run_with_its_actions(monkeypatch):
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id)
    monkeypatch.setattr(soar_service, "get_incident", AsyncMock(return_value=incident))
    run = SoarPlaybookRun(id=uuid.uuid4(), incident_id=incident.id, playbook_id="pb-x", triggered_by=SoarTriggerSource.MANUAL, status=SoarRunStatus.PENDING, created_at=datetime.now(timezone.utc))
    action = _action()
    action.playbook_run_id = run.id
    db = _FakeReadSession(runs=[run], actions=[action])

    fetched_run, actions = await soar_service.get_run(db, tenant_id, incident.id, run.id)

    assert fetched_run is run
    assert actions == [action]


# ── validate_action_parameters ───────────────────────────────────────

def test_validate_action_parameters_returns_a_plain_dict():
    result = soar_service.validate_action_parameters(SoarActionType.ISOLATE_ENDPOINT, {"host_id": "DESKTOP-042"})
    assert result == {"host_id": "DESKTOP-042"}


def test_validate_action_parameters_raises_soar_specific_error_on_failure():
    with pytest.raises(SoarActionParameterError):
        soar_service.validate_action_parameters(SoarActionType.ISOLATE_ENDPOINT, {})


def test_validate_action_parameters_rejects_a_malicious_indicator():
    with pytest.raises(SoarActionParameterError):
        soar_service.validate_action_parameters(SoarActionType.BLOCK_INDICATOR, {"indicator": "1.2.3.4; rm -rf /"})
