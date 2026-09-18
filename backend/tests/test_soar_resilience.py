"""
SafeSOC — SOAR Resilience Tests (Phase 3.5)
Incomplete telemetry must never cost us a response. These cover the
gap found during Phase 3 live verification: a playbook step needing
PRIMARY_IP evidence on an incident whose alerts never carried a
source/destination IP raised SoarActionParameterError out of
create_playbook_run, through evaluate_triggers, and killed the whole
correlation Celery task — losing the incident's other actions, the
other detected chains in that batch, and their notifications.

Three layers are covered, matching the three places the fix lives:
  1. core/soar_playbooks.py — is this step's evidence even there?
  2. services/soar.py       — skip + audit it, keep the rest of the run.
  3. workers/correlation_worker.py — a SOAR fault never stops detection.

The fail-closed guarantee is asserted alongside: a step whose
parameters are present but INVALID is still refused (no action row is
ever created for it), it just no longer takes the run down with it.
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock

import pytest

from app.core.enums import (
    AutonomyClass,
    CorrelationPattern,
    IncidentStatus,
    RecommendationSource,
    SoarActionStatus,
    SoarActionType,
    SoarRunStatus,
    SoarTriggerSource,
    SoarVerificationStatus,
)
from app.core.soar_playbooks import EvidenceField, PlaybookStep, get_playbook, step_evidence_is_available
from app.models.incident import Incident
from app.models.soar import SoarActionExecution, SoarPlaybookRun
from app.services import soar as soar_service
from app.services.incident_evidence import HostEntity, IncidentEvidence, IPEntity, UserEntity
from app.workers import correlation_worker


# ── 1. core/soar_playbooks.py: is the evidence there at all? ─────────

@pytest.mark.parametrize(
    "parameter_field,evidence,expected",
    [
        (EvidenceField.PRIMARY_IP, {"ips": ["203.0.113.5"]}, True),
        (EvidenceField.PRIMARY_IP, {"ips": []}, False),
        (EvidenceField.PRIMARY_IP, {}, False),
        (EvidenceField.PRIMARY_HOST, {"hosts": ["DESKTOP-042"]}, True),
        (EvidenceField.PRIMARY_HOST, {"hosts": []}, False),
        (EvidenceField.PRIMARY_USER, {"users": ["jane.smith"]}, True),
        (EvidenceField.PRIMARY_USER, {"users": []}, False),
        # A step drawing on no evidence at all (static parameters only)
        # is always satisfiable, whatever the incident does or doesn't know.
        (EvidenceField.NONE, {}, True),
    ],
)
def test_step_evidence_is_available(parameter_field, evidence, expected):
    step = PlaybookStep(SoarActionType.ENRICH_INDICATOR, parameter_field)
    assert step_evidence_is_available(step, evidence) is expected


def test_every_playbook_has_at_least_one_step_that_needs_no_evidence():
    """
    Not a rule the code enforces — an observation worth locking down:
    it means every playbook can still do SOMETHING for an incident with
    no resolvable evidence, so the all-steps-skipped path stays the
    rare edge case rather than the norm.
    """
    from app.core.soar_playbooks import SOAR_PLAYBOOKS

    for playbook in SOAR_PLAYBOOKS:
        assert any(step.parameter_field == EvidenceField.NONE for step in playbook.steps), playbook.id


# ── 2. services/soar.py: skip the step, keep the run ─────────────────

class _FakeSoarSession:
    """Mirrors test_soar_service.py's own fake: add/flush/commit assign ids the way a real round-trip would."""

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
        raise AssertionError("create_playbook_run reaches the DB only via get_incident/get_incident_evidence — both mocked here")


def _incident(tenant_id) -> Incident:
    return Incident(
        id=uuid.uuid4(), tenant_id=tenant_id, status=IncidentStatus.OPEN,
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


def _created_actions(db) -> list[SoarActionExecution]:
    return [obj for obj in db.committed if isinstance(obj, SoarActionExecution)]


@pytest.mark.asyncio
async def test_missing_primary_ip_skips_only_that_step(monkeypatch):
    """
    THE Phase 3 live-verification failure, as a regression test.
    pb-credential-brute-force is ENRICH_INDICATOR (PRIMARY_IP) +
    CREATE_INVESTIGATION_ACTION (static). An incident with a host but
    no IP — exactly what authentication-only telemetry produces —
    must still get its investigation action.
    """
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id)
    monkeypatch.setattr(soar_service, "get_incident", AsyncMock(return_value=incident))
    monkeypatch.setattr(soar_service, "get_incident_evidence", AsyncMock(return_value=_evidence(incident.id, hosts=["DESKTOP-042"])))
    monkeypatch.setattr(soar_service, "record_event", AsyncMock())
    db = _FakeSoarSession()

    run = await soar_service.create_playbook_run(db, tenant_id, incident.id, "pb-credential-brute-force")

    actions = _created_actions(db)
    assert [a.action_type for a in actions] == [SoarActionType.CREATE_INVESTIGATION_ACTION]
    assert run.playbook_id == "pb-credential-brute-force"


@pytest.mark.asyncio
async def test_missing_primary_ip_is_audited_with_an_honest_reason(monkeypatch):
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id)
    monkeypatch.setattr(soar_service, "get_incident", AsyncMock(return_value=incident))
    monkeypatch.setattr(soar_service, "get_incident_evidence", AsyncMock(return_value=_evidence(incident.id, hosts=["DESKTOP-042"])))
    record_event_mock = AsyncMock()
    monkeypatch.setattr(soar_service, "record_event", record_event_mock)

    await soar_service.create_playbook_run(_FakeSoarSession(), tenant_id, incident.id, "pb-credential-brute-force")

    skipped = [
        call.kwargs for call in record_event_mock.call_args_list if call.kwargs.get("action") == "soar.action.skipped"
    ]
    assert len(skipped) == 1
    details = skipped[0]["details"]
    assert details["action_type"] == SoarActionType.ENRICH_INDICATOR.value
    assert details["reason"] == "required_evidence_unavailable"
    assert details["detail"] == EvidenceField.PRIMARY_IP.value
    assert details["incident_id"] == str(incident.id)


@pytest.mark.asyncio
async def test_a_skipped_step_creates_no_action_row_at_all(monkeypatch):
    """
    'Don't silently pretend an action executed': a skipped step leaves
    no SoarActionExecution behind, in any status. Nothing can later
    read it as attempted, failed, or rejected — the audit event is the
    only record, and it says exactly what happened.
    """
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id)
    monkeypatch.setattr(soar_service, "get_incident", AsyncMock(return_value=incident))
    monkeypatch.setattr(soar_service, "get_incident_evidence", AsyncMock(return_value=_evidence(incident.id, hosts=["DESKTOP-042"])))
    monkeypatch.setattr(soar_service, "record_event", AsyncMock())
    db = _FakeSoarSession()

    await soar_service.create_playbook_run(db, tenant_id, incident.id, "pb-credential-brute-force")

    assert all(a.action_type != SoarActionType.ENRICH_INDICATOR for a in _created_actions(db))


@pytest.mark.asyncio
async def test_full_evidence_still_creates_every_action(monkeypatch):
    """The complete-telemetry path is untouched by the skip logic."""
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id)
    monkeypatch.setattr(soar_service, "get_incident", AsyncMock(return_value=incident))
    monkeypatch.setattr(
        soar_service, "get_incident_evidence",
        AsyncMock(return_value=_evidence(incident.id, hosts=["DESKTOP-042"], ips=["203.0.113.5"], users=["jane.smith"])),
    )
    record_event_mock = AsyncMock()
    monkeypatch.setattr(soar_service, "record_event", record_event_mock)
    db = _FakeSoarSession()

    await soar_service.create_playbook_run(db, tenant_id, incident.id, "pb-successful-compromise")

    assert len(_created_actions(db)) == 4
    assert not [c for c in record_event_mock.call_args_list if c.kwargs.get("action") == "soar.action.skipped"]


@pytest.mark.asyncio
async def test_invalid_parameters_are_refused_but_do_not_stop_the_other_actions(monkeypatch):
    """
    Fail-closed, contained. The IP evidence IS present but isn't a
    valid indicator, so BLOCK_INDICATOR — the step that would enforce
    something on it — is refused and never created, while
    pb-data-exfiltration's other steps still proceed. The skip reason
    distinguishes this from missing evidence: one is a refusal, the
    other is an absence.

    ENRICH_INDICATOR is deliberately NOT expected to be refused here.
    Its parameter model (schemas/soar.py::EnrichIndicatorParams)
    accepts any string, unlike BlockIndicatorParams' IP/domain
    validator — a read-only threat-intel lookup and a firewall block
    don't warrant the same contract. That asymmetry predates this
    phase; what matters for fail-closed is that the ENFORCEMENT action
    never gets built from an unvalidated value.
    """
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id)
    monkeypatch.setattr(soar_service, "get_incident", AsyncMock(return_value=incident))
    monkeypatch.setattr(
        soar_service, "get_incident_evidence",
        AsyncMock(return_value=_evidence(incident.id, ips=["not a valid indicator at all"])),
    )
    record_event_mock = AsyncMock()
    monkeypatch.setattr(soar_service, "record_event", record_event_mock)
    db = _FakeSoarSession()

    await soar_service.create_playbook_run(db, tenant_id, incident.id, "pb-data-exfiltration")

    created = [a.action_type for a in _created_actions(db)]
    assert SoarActionType.BLOCK_INDICATOR not in created  # refused
    assert SoarActionType.ADD_INCIDENT_NOTE in created    # unaffected by its sibling's refusal
    skipped = [
        c.kwargs["details"] for c in record_event_mock.call_args_list if c.kwargs.get("action") == "soar.action.skipped"
    ]
    assert [d["action_type"] for d in skipped] == [SoarActionType.BLOCK_INDICATOR.value]
    assert skipped[0]["reason"] == "parameter_validation_failed"


@pytest.mark.asyncio
async def test_a_malicious_indicator_is_never_turned_into_an_action(monkeypatch):
    """The command-injection-shaped indicator from test_soar_service.py, now via the full creation path."""
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id)
    monkeypatch.setattr(soar_service, "get_incident", AsyncMock(return_value=incident))
    monkeypatch.setattr(
        soar_service, "get_incident_evidence",
        AsyncMock(return_value=_evidence(incident.id, ips=["1.2.3.4; rm -rf /"])),
    )
    monkeypatch.setattr(soar_service, "record_event", AsyncMock())
    db = _FakeSoarSession()

    await soar_service.create_playbook_run(db, tenant_id, incident.id, "pb-data-exfiltration")

    assert all(a.action_type != SoarActionType.BLOCK_INDICATOR for a in _created_actions(db))


# ── evaluate_triggers: the all-skipped run must not hang ─────────────

class _FakeTriggerSession:
    """Serves evaluate_triggers' own three queries: the advisory lock, the existing-run check, and the created-actions fetch."""

    def __init__(self, actions):
        self.actions = actions
        self.commits = 0

    async def execute(self, stmt, params=None):
        text_form = str(stmt)
        if "pg_advisory_xact_lock" in text_form:
            return Mock()
        if "soar_action_executions" in text_form:
            return _Result(self.actions)
        return _Result([])  # no existing run for this (incident, playbook)

    async def commit(self):
        self.commits += 1


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None


@pytest.mark.asyncio
async def test_a_run_with_every_step_skipped_is_cancelled_not_left_awaiting_approval(monkeypatch):
    """
    A run holding zero actions has nothing to execute and nothing to
    approve. Sending it to AWAITING_APPROVAL (the branch a run with no
    AUTOMATIC actions would otherwise take) would strand it there
    forever, showing an analyst a pending decision that can never be
    made. CANCELLED — an existing status, already legal from PENDING —
    is the honest end state.
    """
    tenant_id, incident_id = uuid.uuid4(), uuid.uuid4()
    run = SoarPlaybookRun(
        id=uuid.uuid4(), incident_id=incident_id, playbook_id="pb-successful-compromise",
        triggered_by=SoarTriggerSource.AUTO_TRIGGER, status=SoarRunStatus.PENDING,
    )
    monkeypatch.setattr(soar_service, "create_playbook_run", AsyncMock(return_value=run))
    record_event_mock = AsyncMock()
    monkeypatch.setattr(soar_service, "record_event", record_event_mock)
    db = _FakeTriggerSession(actions=[])

    result = await soar_service.evaluate_triggers(db, tenant_id, incident_id, CorrelationPattern.SUCCESSFUL_COMPROMISE, 0.9)

    assert result is not None
    returned_run, queued = result
    assert returned_run.status == SoarRunStatus.CANCELLED
    assert returned_run.completed_at is not None
    assert queued == []  # nothing queued for execution
    cancelled = [c.kwargs for c in record_event_mock.call_args_list if c.kwargs.get("action") == "soar.playbook_run.cancelled"]
    assert len(cancelled) == 1
    assert cancelled[0]["details"]["reason"] == "no_actions_instantiable"


@pytest.mark.asyncio
async def test_a_partially_skipped_run_still_queues_its_surviving_automatic_actions(monkeypatch):
    """One skipped step doesn't stop the actions that DID resolve from being queued."""
    tenant_id, incident_id = uuid.uuid4(), uuid.uuid4()
    run = SoarPlaybookRun(
        id=uuid.uuid4(), incident_id=incident_id, playbook_id="pb-successful-compromise",
        triggered_by=SoarTriggerSource.AUTO_TRIGGER, status=SoarRunStatus.PENDING,
    )
    surviving = SoarActionExecution(
        id=uuid.uuid4(), playbook_run_id=run.id, action_type=SoarActionType.ADD_INCIDENT_NOTE,
        parameters={"note": "x"}, autonomy_class=AutonomyClass.AUTOMATIC,
        recommended_by=RecommendationSource.PLAYBOOK_AUTO, status=SoarActionStatus.PENDING,
        verification_status=SoarVerificationStatus.NOT_VERIFIED,
    )
    monkeypatch.setattr(soar_service, "create_playbook_run", AsyncMock(return_value=run))
    monkeypatch.setattr(soar_service, "record_event", AsyncMock())
    db = _FakeTriggerSession(actions=[surviving])

    run_out, queued = await soar_service.evaluate_triggers(
        db, tenant_id, incident_id, CorrelationPattern.SUCCESSFUL_COMPROMISE, 0.9
    )

    assert run_out.status == SoarRunStatus.RUNNING
    assert queued == [surviving.id]


# ── 3. correlation_worker: SOAR must never take detection down ───────

class _RollbackSession:
    def __init__(self):
        self.rollbacks = 0

    async def rollback(self):
        self.rollbacks += 1


class _FakeSessionCM:
    def __init__(self, session):
        self.session = session

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, *args):
        return False


def _chain(pattern: CorrelationPattern):
    from app.services.correlation import DetectedChain

    return DetectedChain(
        pattern=pattern, confidence=0.9, alert_ids=("a1",), mitre_technique_ids=("T1110",), mitre_tactic="Credential Access",
    )


def _worker_doc(tenant_id) -> dict:
    return {
        "alert_id": "abc-123", "tenant_id": str(tenant_id), "host_id": "DESKTOP-042",
        "log_type": "authentication", "action": "failed_login", "severity": "low",
    }


def _mock_worker_pipeline(monkeypatch, tenant_id, chains, session):
    incident = Incident(id=uuid.uuid4(), tenant_id=tenant_id, status=IncidentStatus.OPEN, alert_ids=["a1"])
    monkeypatch.setattr(correlation_worker, "get_alert_by_id", AsyncMock(return_value=_worker_doc(tenant_id)))
    monkeypatch.setattr(correlation_worker, "add_event", AsyncMock())
    monkeypatch.setattr(correlation_worker, "evaluate_host", AsyncMock(return_value=chains))
    monkeypatch.setattr(correlation_worker, "worker_session_factory", lambda: _FakeSessionCM(session))
    create_mock = AsyncMock(return_value=incident)
    monkeypatch.setattr(correlation_worker, "create_or_merge_incident", create_mock)
    notify_mock = Mock()
    monkeypatch.setattr(correlation_worker, "notify_attack_chain", notify_mock)
    publish_mock = AsyncMock()
    monkeypatch.setattr(correlation_worker, "publish_event", publish_mock)
    return incident, create_mock, notify_mock, publish_mock


@pytest.mark.asyncio
async def test_a_soar_failure_does_not_crash_the_correlation_task(monkeypatch):
    tenant_id = uuid.uuid4()
    session = _RollbackSession()
    _mock_worker_pipeline(monkeypatch, tenant_id, [_chain(CorrelationPattern.CREDENTIAL_BRUTE_FORCE)], session)
    monkeypatch.setattr(
        correlation_worker.soar_service, "evaluate_triggers", AsyncMock(side_effect=RuntimeError("SOAR exploded"))
    )

    await correlation_worker._evaluate_correlation_async("abc-123")  # must not raise

    assert session.rollbacks == 1  # session left usable for whatever comes next


@pytest.mark.asyncio
async def test_one_chains_soar_failure_does_not_stop_the_next_chains_playbook(monkeypatch):
    """
    Two detected chains in one batch. The first chain's playbook blows
    up; the second must still be evaluated, still create its incident,
    still notify, and still queue its own automatic actions.
    """
    tenant_id = uuid.uuid4()
    session = _RollbackSession()
    chains = [_chain(CorrelationPattern.CREDENTIAL_BRUTE_FORCE), _chain(CorrelationPattern.SUCCESSFUL_COMPROMISE)]
    incident, create_mock, notify_mock, publish_mock = _mock_worker_pipeline(monkeypatch, tenant_id, chains, session)

    good_run = SoarPlaybookRun(
        id=uuid.uuid4(), incident_id=incident.id, playbook_id="pb-successful-compromise",
        triggered_by=SoarTriggerSource.AUTO_TRIGGER, status=SoarRunStatus.RUNNING,
    )
    surviving_action_id = uuid.uuid4()
    monkeypatch.setattr(
        correlation_worker.soar_service, "evaluate_triggers",
        AsyncMock(side_effect=[RuntimeError("first playbook exploded"), (good_run, [surviving_action_id])]),
    )
    delay_mock = Mock()
    monkeypatch.setattr(correlation_worker.execute_soar_action, "delay", delay_mock)

    await correlation_worker._evaluate_correlation_async("abc-123")

    assert create_mock.await_count == 2   # both chains still became incidents
    assert notify_mock.call_count == 2    # both still notified
    assert publish_mock.await_count == 2  # both still pushed to the dashboard
    delay_mock.assert_called_once_with(str(surviving_action_id))  # the healthy playbook's action still queued


@pytest.mark.asyncio
async def test_a_soar_failure_is_logged_as_an_error_not_swallowed(monkeypatch):
    tenant_id = uuid.uuid4()
    session = _RollbackSession()
    _mock_worker_pipeline(monkeypatch, tenant_id, [_chain(CorrelationPattern.CREDENTIAL_BRUTE_FORCE)], session)
    monkeypatch.setattr(
        correlation_worker.soar_service, "evaluate_triggers", AsyncMock(side_effect=RuntimeError("SOAR exploded"))
    )
    errors = []
    monkeypatch.setattr(correlation_worker.logger, "error", lambda msg, **kw: errors.append((msg, kw)))

    await correlation_worker._evaluate_correlation_async("abc-123")

    assert len(errors) == 1
    message, fields = errors[0]
    assert "soar" in message.lower()
    assert fields["error_type"] == "RuntimeError"
    assert fields["pattern"] == "credential_brute_force"
