"""
SafeSOC — SOAR End-to-End Integration Test (Phase 2)
Exercises the REAL functions in sequence — services.soar.evaluate_triggers
-> services.soar.create_playbook_run -> services.soar_execution.execute_action
-> audit/realtime — against a fake session capable of serving the real
queries each one issues (dispatched by SQLAlchemy target type + bound
parameter values, not hand-simulated SQL). Only the true external
boundaries are mocked: get_incident, get_incident_evidence (OpenSearch),
enrichment (VirusTotal/AbuseIPDB), and audit/realtime's own I/O.

This is deliberately the one place in the SOAR test suite that chains
every real function together rather than boundary-mocking each one in
isolation — full real-Postgres proof is still left to live verification
against Docker (this codebase's own established convention — see e.g.
test_threat_analytics.py's docstring — for anything needing genuine
tenant-scoped SQL filtering), but this gives durable, fast regression
coverage for the wiring itself.
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from app.core.enums import CorrelationPattern, IncidentStatus, SoarActionStatus, SoarActionType, SoarRunStatus, SoarVerificationStatus
from app.models.incident import Incident
from app.models.soar import SoarActionExecution, SoarPlaybookRun
from app.services import soar as soar_service
from app.services import soar_execution
from app.services.incident_evidence import HostEntity, IncidentEvidence, IPEntity, UserEntity


class _Result:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None


def _bound_values(stmt) -> set:
    try:
        return set(stmt.compile().params.values())
    except Exception:
        return set()


class _FakeIntegrationSession:
    """Serves every real query services/soar.py and services/soar_execution.py issue for one incident's worth of state, dispatched by target type + the statement's own bound parameter values."""

    def __init__(self, incident: Incident):
        self.incident = incident
        self.runs: list[SoarPlaybookRun] = []
        self.actions: list[SoarActionExecution] = []
        self._pending: list = []

    def add(self, obj) -> None:
        self._pending.append(obj)

    async def flush(self) -> None:
        for obj in self._pending:
            if getattr(obj, "id", None) is None:
                obj.id = uuid.uuid4()

    async def commit(self) -> None:
        await self.flush()
        now = datetime.now(timezone.utc)
        for obj in self._pending:
            if getattr(obj, "created_at", None) is None:
                obj.created_at = now
            if isinstance(obj, SoarPlaybookRun) and obj not in self.runs:
                self.runs.append(obj)
            elif isinstance(obj, SoarActionExecution) and obj not in self.actions:
                self.actions.append(obj)
        self._pending = []

    async def refresh(self, obj) -> None:
        pass

    async def execute(self, stmt, params=None):
        if params is not None and "lock_key" in params:
            return _Result([])

        target = getattr(stmt, "column_descriptions", [{}])[0].get("type") if hasattr(stmt, "column_descriptions") else None
        bound = _bound_values(stmt)

        if target is Incident:
            return _Result([self.incident] if self.incident and self.incident.id in bound else [self.incident] if self.incident else [])

        if target is SoarPlaybookRun:
            by_id = [r for r in self.runs if r.id in bound]
            if by_id:
                return _Result(by_id)
            by_incident_and_playbook = [r for r in self.runs if r.incident_id in bound and r.playbook_id in bound]
            if by_incident_and_playbook:
                return _Result(by_incident_and_playbook)
            by_incident = [r for r in self.runs if r.incident_id in bound]
            return _Result(by_incident)

        if target is SoarActionExecution:
            by_id = [a for a in self.actions if a.id in bound]
            if by_id:
                return _Result(by_id)
            by_run = [a for a in self.actions if a.playbook_run_id in bound]
            return _Result(by_run)

        return _Result([])


def _incident(tenant_id) -> Incident:
    return Incident(id=uuid.uuid4(), tenant_id=tenant_id, status=IncidentStatus.OPEN, alert_ids=["a1"], category=None, confidence=None, tags=[], created_at=datetime.now(timezone.utc))


@pytest.fixture(autouse=True)
def _mock_audit_and_realtime(monkeypatch):
    monkeypatch.setattr(soar_service, "record_event", AsyncMock())
    monkeypatch.setattr(soar_execution, "record_event", AsyncMock())
    monkeypatch.setattr(soar_execution, "publish_event", AsyncMock())


@pytest.mark.asyncio
async def test_real_incident_to_playbook_to_action_to_verification_to_audit(monkeypatch):
    """
    The full chain the task's Integration section calls for: a real
    incident, a real correlation pattern match, a real playbook run and
    its actions, real dispatched execution for every AUTOMATIC action,
    real verification, and a real audit trail — end to end.
    """
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id)
    db = _FakeIntegrationSession(incident)

    evidence = IncidentEvidence(
        incident_id=incident.id,
        hosts=[HostEntity(host_id="DESKTOP-042", alert_count=3)],
        ips=[IPEntity(ip="203.0.113.5", roles=["source"], alert_count=3)],
        users=[UserEntity(user="tom.thompson", alert_count=3)],
        cloud_resources=[],
    )
    monkeypatch.setattr(soar_service, "get_incident", AsyncMock(return_value=incident))
    monkeypatch.setattr(soar_service, "get_incident_evidence", AsyncMock(return_value=evidence))
    monkeypatch.setattr(soar_execution, "get_incident_evidence", AsyncMock(return_value=evidence))

    from app.schemas.log import TIResult
    monkeypatch.setattr(soar_execution.enrichment_service, "enrich_indicator", AsyncMock(return_value=TIResult(is_malicious=True, vt_malicious=8, vt_total=70)))

    # Real note/investigation-action creation would need a real analyst
    # user + investigation session round trip — outside this fake
    # session's scope, so the two handlers that need them are boundary-
    # mocked at their own service-call level (their own logic is fully
    # covered in test_soar_execution.py's dedicated handler tests).
    monkeypatch.setattr(soar_execution, "_get_or_create_system_actor", AsyncMock(return_value=uuid.uuid4()))
    from app.models.incident import IncidentNote
    monkeypatch.setattr(soar_execution.incidents_service, "add_note", AsyncMock(return_value=IncidentNote(id=uuid.uuid4(), incident_id=incident.id, author_user_id=uuid.uuid4(), body="x", created_at=datetime.now(timezone.utc))))

    # 1. TRIGGER — a real detected pattern matches pb-credential-brute-force.
    trigger_result = await soar_service.evaluate_triggers(db, tenant_id, incident.id, CorrelationPattern.CREDENTIAL_BRUTE_FORCE, confidence=0.9)
    assert trigger_result is not None
    run, automatic_action_ids = trigger_result
    assert run.playbook_id == "pb-credential-brute-force"
    assert run.status == SoarRunStatus.RUNNING
    assert len(automatic_action_ids) == 2  # ENRICH_INDICATOR + CREATE_INVESTIGATION_ACTION, both AUTOMATIC

    # CREATE_INVESTIGATION_ACTION needs a real investigation session —
    # mock that one handler's own service call directly (its own logic
    # is covered in test_soar_execution.py).
    from app.models.investigation_session import InvestigationAction, InvestigationSession
    session = InvestigationSession(id=uuid.uuid4(), incident_id=incident.id, created_by_user_id=uuid.uuid4(), created_at=datetime.now(timezone.utc))
    monkeypatch.setattr(soar_execution, "_get_or_create_soar_session", AsyncMock(return_value=session))
    monkeypatch.setattr(
        soar_execution.investigation_session_service, "create_action",
        AsyncMock(return_value=InvestigationAction(id=uuid.uuid4(), session_id=session.id, description="x", created_by_user_id=uuid.uuid4(), created_at=datetime.now(timezone.utc))),
    )

    # 2. EXECUTE — every queued AUTOMATIC action runs for real through execute_action.
    executed = []
    for action_id in automatic_action_ids:
        executed.append(await soar_execution.execute_action(db, action_id))

    # 3. VERIFY — both actions genuinely succeeded and were verified.
    for action in executed:
        assert action.status == SoarActionStatus.SUCCEEDED
        assert action.verification_status == SoarVerificationStatus.VERIFIED
        assert action.result["success"] is True

    enrich_action = next(a for a in executed if a.action_type == SoarActionType.ENRICH_INDICATOR)
    assert enrich_action.result["is_malicious"] is True

    # 4. AUDIT — every phase wrote an audit event: trigger, queue, start, succeed, verify.
    audit_calls = [call.kwargs.get("action") or call.args[2] for call in soar_execution.record_event.call_args_list]
    assert "soar.action.started" in audit_calls
    assert "soar.action.succeeded" in audit_calls
    assert "soar.action.verified" in audit_calls
    trigger_audit_calls = [call.kwargs.get("action") or call.args[2] for call in soar_service.record_event.call_args_list]
    assert "soar.playbook.triggered" in trigger_audit_calls
    assert "soar.action.queued" in trigger_audit_calls

    # 5. Run completion — both actions terminal and successful -> run auto-completes.
    await soar_execution._maybe_complete_run(db, run)
    assert run.status == SoarRunStatus.COMPLETED


@pytest.mark.asyncio
async def test_re_evaluating_the_same_incident_does_not_duplicate_the_run_or_re_execute(monkeypatch):
    """A second correlation pass on the same evolving incident (create_or_merge_incident's own merge case) must not create a second run or re-run anything."""
    tenant_id = uuid.uuid4()
    incident = _incident(tenant_id)
    db = _FakeIntegrationSession(incident)

    evidence = IncidentEvidence(incident_id=incident.id, hosts=[], ips=[IPEntity(ip="203.0.113.5", roles=["source"], alert_count=1)], users=[], cloud_resources=[])
    monkeypatch.setattr(soar_service, "get_incident", AsyncMock(return_value=incident))
    monkeypatch.setattr(soar_service, "get_incident_evidence", AsyncMock(return_value=evidence))

    first = await soar_service.evaluate_triggers(db, tenant_id, incident.id, CorrelationPattern.CREDENTIAL_BRUTE_FORCE, confidence=0.9)
    second = await soar_service.evaluate_triggers(db, tenant_id, incident.id, CorrelationPattern.CREDENTIAL_BRUTE_FORCE, confidence=0.95)

    assert first is not None
    assert second is None  # idempotent — no duplicate run
    assert len(db.runs) == 1
