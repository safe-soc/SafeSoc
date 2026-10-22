"""
SafeSOC — Correlation Worker Tests
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock

import pytest

from app.core.enums import CorrelationPattern, SoarRunStatus
from app.models.incident import Incident, IncidentStatus
from app.models.soar import SoarPlaybookRun
from app.services.correlation import DetectedChain
from app.tasks.celery_app import celery_app
from app.workers import correlation_worker


class _FakeSessionCM:
    async def __aenter__(self):
        return "fake-db-session"

    async def __aexit__(self, *args):
        return False


def test_evaluate_correlation_task_is_registered_with_celery():
    assert "app.workers.correlation_worker.evaluate_correlation" in celery_app.tasks


@pytest.mark.asyncio
async def test_evaluate_correlation_async_adds_the_event_then_evaluates_the_window(monkeypatch):
    doc = {
        "alert_id": "abc-123",
        "tenant_id": "acme-corp",
        "host_id": "DESKTOP-042",
        "log_type": "authentication",
        "action": "failed_login",
        "severity": "low",
        "destination_ip": None,
    }
    monkeypatch.setattr(correlation_worker, "get_alert_by_id", AsyncMock(return_value=doc))
    mock_add_event = AsyncMock()
    monkeypatch.setattr(correlation_worker, "add_event", mock_add_event)
    mock_evaluate_host = AsyncMock(return_value=[])
    monkeypatch.setattr(correlation_worker, "evaluate_host", mock_evaluate_host)

    await correlation_worker._evaluate_correlation_async("abc-123")

    mock_add_event.assert_called_once()
    tenant_arg, host_arg, event_arg = mock_add_event.call_args.args
    assert tenant_arg == "acme-corp"
    assert host_arg == "DESKTOP-042"
    assert event_arg["alert_id"] == "abc-123"
    assert event_arg["action"] == "failed_login"

    mock_evaluate_host.assert_called_once_with("acme-corp", "DESKTOP-042")


# ── Event-time scoring (ADR-011) ─────────────────────────────────────

@pytest.mark.asyncio
async def test_the_event_is_scored_by_its_own_timestamp_not_processing_time(monkeypatch):
    """
    The actual defect: one Celery task per alert, running concurrently,
    scored the correlation window at task-completion time — so the
    order-sensitive detectors saw a two-event chain in either order.
    """
    doc = {
        "alert_id": "abc-123",
        "tenant_id": "acme-corp",
        "host_id": "DESKTOP-042",
        "log_type": "privilege",
        "action": "permission_change",
        "severity": "critical",
        "timestamp": "2026-08-26T09:15:42Z",
    }
    monkeypatch.setattr(correlation_worker, "get_alert_by_id", AsyncMock(return_value=doc))
    mock_add_event = AsyncMock()
    monkeypatch.setattr(correlation_worker, "add_event", mock_add_event)
    monkeypatch.setattr(correlation_worker, "evaluate_host", AsyncMock(return_value=[]))

    await correlation_worker._evaluate_correlation_async("abc-123")

    expected = datetime(2026, 8, 26, 9, 15, 42, tzinfo=timezone.utc).timestamp()
    assert mock_add_event.call_args.kwargs["timestamp"] == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("raw, expected", [
    ("2026-08-26T09:15:42Z", datetime(2026, 8, 26, 9, 15, 42, tzinfo=timezone.utc)),
    ("2026-08-26T09:15:42+00:00", datetime(2026, 8, 26, 9, 15, 42, tzinfo=timezone.utc)),
    ("2026-08-26T14:45:42+05:30", datetime(2026, 8, 26, 9, 15, 42, tzinfo=timezone.utc)),
])
async def test_event_timestamp_parses_both_z_and_offset_forms(raw, expected):
    assert correlation_worker._event_timestamp({"timestamp": raw}, "abc-123") == expected.timestamp()


@pytest.mark.asyncio
@pytest.mark.parametrize("doc", [{}, {"timestamp": None}, {"timestamp": "not-a-timestamp"}, {"timestamp": 1700000000}])
async def test_event_timestamp_falls_back_to_now_for_an_unusable_timestamp(doc, monkeypatch):
    """Degrades to the old processing-time behavior for that one event rather than dropping it from correlation."""
    monkeypatch.setattr(correlation_worker.time, "time", lambda: 1_700_000_000.0)

    assert correlation_worker._event_timestamp(doc, "abc-123") == 1_700_000_000.0


@pytest.mark.asyncio
async def test_an_unparseable_timestamp_is_logged_as_a_warning(monkeypatch):
    warnings = []
    monkeypatch.setattr(correlation_worker.logger, "warning", lambda msg, **kw: warnings.append((msg, kw)))

    correlation_worker._event_timestamp({"timestamp": "nonsense"}, "abc-123")

    assert len(warnings) == 1
    assert warnings[0][1]["alert_id"] == "abc-123"


@pytest.mark.asyncio
async def test_evaluate_correlation_async_creates_an_incident_and_logs_each_detected_chain(monkeypatch):
    tenant_id = uuid.uuid4()
    doc = {
        "alert_id": "abc-123",
        "tenant_id": str(tenant_id),
        "host_id": "DESKTOP-042",
        "log_type": "authentication",
        "action": "failed_login",
        "severity": "low",
    }
    chain = DetectedChain(
        pattern=CorrelationPattern.CREDENTIAL_BRUTE_FORCE,
        confidence=0.8,
        alert_ids=("a1", "a2"),
        mitre_technique_ids=("T1110",),
        mitre_tactic="Credential Access",
    )
    incident = Incident(id=uuid.uuid4(), tenant_id=tenant_id, status=IncidentStatus.OPEN, alert_ids=["a1", "a2"])

    monkeypatch.setattr(correlation_worker, "get_alert_by_id", AsyncMock(return_value=doc))
    monkeypatch.setattr(correlation_worker, "add_event", AsyncMock())
    monkeypatch.setattr(correlation_worker, "evaluate_host", AsyncMock(return_value=[chain]))
    monkeypatch.setattr(correlation_worker, "worker_session_factory", lambda: _FakeSessionCM())
    mock_create_or_merge = AsyncMock(return_value=incident)
    monkeypatch.setattr(correlation_worker, "create_or_merge_incident", mock_create_or_merge)
    monkeypatch.setattr(correlation_worker, "notify_attack_chain", Mock())
    monkeypatch.setattr(correlation_worker, "publish_event", AsyncMock())
    monkeypatch.setattr(correlation_worker.soar_service, "evaluate_triggers", AsyncMock(return_value=None))

    logged = []
    monkeypatch.setattr(correlation_worker.logger, "info", lambda msg, **kw: logged.append((msg, kw)))

    await correlation_worker._evaluate_correlation_async("abc-123")

    mock_create_or_merge.assert_called_once_with("fake-db-session", tenant_id, "DESKTOP-042", chain)

    assert len(logged) == 1
    message, fields = logged[0]
    assert "chain" in message.lower()
    assert fields["pattern"] == "credential_brute_force"
    assert fields["alert_ids"] == ["a1", "a2"]
    assert fields["incident_id"] == str(incident.id)


@pytest.mark.asyncio
async def test_evaluate_correlation_async_notifies_for_each_detected_chain(monkeypatch):
    """SS-056 AC: a new attack chain triggers a notification."""
    tenant_id = uuid.uuid4()
    doc = {
        "alert_id": "abc-123",
        "tenant_id": str(tenant_id),
        "host_id": "DESKTOP-042",
        "log_type": "authentication",
        "action": "failed_login",
        "severity": "low",
    }
    chain = DetectedChain(
        pattern=CorrelationPattern.CREDENTIAL_BRUTE_FORCE,
        confidence=0.8,
        alert_ids=("a1", "a2"),
        mitre_technique_ids=("T1110",),
        mitre_tactic="Credential Access",
    )
    incident = Incident(id=uuid.uuid4(), tenant_id=tenant_id, status=IncidentStatus.OPEN, alert_ids=["a1", "a2"])

    monkeypatch.setattr(correlation_worker, "get_alert_by_id", AsyncMock(return_value=doc))
    monkeypatch.setattr(correlation_worker, "add_event", AsyncMock())
    monkeypatch.setattr(correlation_worker, "evaluate_host", AsyncMock(return_value=[chain]))
    monkeypatch.setattr(correlation_worker, "worker_session_factory", lambda: _FakeSessionCM())
    monkeypatch.setattr(correlation_worker, "create_or_merge_incident", AsyncMock(return_value=incident))
    mock_notify = Mock()
    monkeypatch.setattr(correlation_worker, "notify_attack_chain", mock_notify)
    monkeypatch.setattr(correlation_worker, "publish_event", AsyncMock())
    monkeypatch.setattr(correlation_worker.soar_service, "evaluate_triggers", AsyncMock(return_value=None))

    await correlation_worker._evaluate_correlation_async("abc-123")

    mock_notify.assert_called_once_with("DESKTOP-042", chain, incident.id)


@pytest.mark.asyncio
async def test_evaluate_correlation_async_publishes_a_realtime_event_for_each_detected_chain(monkeypatch):
    """SS-063 AC: a detected chain pushes a live dashboard update."""
    tenant_id = uuid.uuid4()
    doc = {
        "alert_id": "abc-123",
        "tenant_id": str(tenant_id),
        "host_id": "DESKTOP-042",
        "log_type": "authentication",
        "action": "failed_login",
        "severity": "low",
    }
    chain = DetectedChain(
        pattern=CorrelationPattern.CREDENTIAL_BRUTE_FORCE,
        confidence=0.8,
        alert_ids=("a1", "a2"),
        mitre_technique_ids=("T1110",),
        mitre_tactic="Credential Access",
    )
    incident = Incident(id=uuid.uuid4(), tenant_id=tenant_id, status=IncidentStatus.OPEN, alert_ids=["a1", "a2"])

    monkeypatch.setattr(correlation_worker, "get_alert_by_id", AsyncMock(return_value=doc))
    monkeypatch.setattr(correlation_worker, "add_event", AsyncMock())
    monkeypatch.setattr(correlation_worker, "evaluate_host", AsyncMock(return_value=[chain]))
    monkeypatch.setattr(correlation_worker, "worker_session_factory", lambda: _FakeSessionCM())
    monkeypatch.setattr(correlation_worker, "create_or_merge_incident", AsyncMock(return_value=incident))
    monkeypatch.setattr(correlation_worker, "notify_attack_chain", Mock())
    mock_publish = AsyncMock()
    monkeypatch.setattr(correlation_worker, "publish_event", mock_publish)
    monkeypatch.setattr(correlation_worker.soar_service, "evaluate_triggers", AsyncMock(return_value=None))

    await correlation_worker._evaluate_correlation_async("abc-123")

    mock_publish.assert_called_once_with(
        str(tenant_id),
        "chain_detected",
        {
            "incident_id": str(incident.id),
            "host_id": "DESKTOP-042",
            "pattern": "credential_brute_force",
            "confidence": 0.8,
        },
    )


@pytest.mark.asyncio
async def test_evaluate_correlation_async_queues_automatic_soar_actions_when_a_playbook_triggers(monkeypatch):
    """SOAR Phase 2: a detected chain that matches a playbook queues that playbook's AUTOMATIC actions via workers.soar_worker."""
    tenant_id = uuid.uuid4()
    doc = {
        "alert_id": "abc-123", "tenant_id": str(tenant_id), "host_id": "DESKTOP-042",
        "log_type": "authentication", "action": "failed_login", "severity": "low",
    }
    chain = DetectedChain(
        pattern=CorrelationPattern.CREDENTIAL_BRUTE_FORCE, confidence=0.8,
        alert_ids=("a1", "a2"), mitre_technique_ids=("T1110",), mitre_tactic="Credential Access",
    )
    incident = Incident(id=uuid.uuid4(), tenant_id=tenant_id, status=IncidentStatus.OPEN, alert_ids=["a1", "a2"])
    run = SoarPlaybookRun(id=uuid.uuid4(), incident_id=incident.id, playbook_id="pb-credential-brute-force", status=SoarRunStatus.RUNNING)
    action_id_1, action_id_2 = uuid.uuid4(), uuid.uuid4()

    monkeypatch.setattr(correlation_worker, "get_alert_by_id", AsyncMock(return_value=doc))
    monkeypatch.setattr(correlation_worker, "add_event", AsyncMock())
    monkeypatch.setattr(correlation_worker, "evaluate_host", AsyncMock(return_value=[chain]))
    monkeypatch.setattr(correlation_worker, "worker_session_factory", lambda: _FakeSessionCM())
    monkeypatch.setattr(correlation_worker, "create_or_merge_incident", AsyncMock(return_value=incident))
    monkeypatch.setattr(correlation_worker, "notify_attack_chain", Mock())
    monkeypatch.setattr(correlation_worker, "publish_event", AsyncMock())
    monkeypatch.setattr(correlation_worker.soar_service, "evaluate_triggers", AsyncMock(return_value=(run, [action_id_1, action_id_2])))
    mock_queue = Mock()
    monkeypatch.setattr(correlation_worker.execute_soar_action, "delay", mock_queue)

    await correlation_worker._evaluate_correlation_async("abc-123")

    correlation_worker.soar_service.evaluate_triggers.assert_called_once_with(
        "fake-db-session", tenant_id, incident.id, chain.pattern, chain.confidence
    )
    assert mock_queue.call_args_list == [((str(action_id_1),),), ((str(action_id_2),),)]


@pytest.mark.asyncio
async def test_evaluate_correlation_async_queues_nothing_when_no_playbook_matches(monkeypatch):
    tenant_id = uuid.uuid4()
    doc = {
        "alert_id": "abc-123", "tenant_id": str(tenant_id), "host_id": "DESKTOP-042",
        "log_type": "authentication", "action": "failed_login", "severity": "low",
    }
    chain = DetectedChain(
        pattern=CorrelationPattern.CREDENTIAL_BRUTE_FORCE, confidence=0.8,
        alert_ids=("a1", "a2"), mitre_technique_ids=("T1110",), mitre_tactic="Credential Access",
    )
    incident = Incident(id=uuid.uuid4(), tenant_id=tenant_id, status=IncidentStatus.OPEN, alert_ids=["a1", "a2"])

    monkeypatch.setattr(correlation_worker, "get_alert_by_id", AsyncMock(return_value=doc))
    monkeypatch.setattr(correlation_worker, "add_event", AsyncMock())
    monkeypatch.setattr(correlation_worker, "evaluate_host", AsyncMock(return_value=[chain]))
    monkeypatch.setattr(correlation_worker, "worker_session_factory", lambda: _FakeSessionCM())
    monkeypatch.setattr(correlation_worker, "create_or_merge_incident", AsyncMock(return_value=incident))
    monkeypatch.setattr(correlation_worker, "notify_attack_chain", Mock())
    monkeypatch.setattr(correlation_worker, "publish_event", AsyncMock())
    monkeypatch.setattr(correlation_worker.soar_service, "evaluate_triggers", AsyncMock(return_value=None))
    mock_queue = Mock()
    monkeypatch.setattr(correlation_worker.execute_soar_action, "delay", mock_queue)

    await correlation_worker._evaluate_correlation_async("abc-123")

    mock_queue.assert_not_called()


@pytest.mark.asyncio
async def test_evaluate_correlation_async_no_ops_when_alert_not_found(monkeypatch):
    monkeypatch.setattr(correlation_worker, "get_alert_by_id", AsyncMock(return_value=None))
    mock_add_event = AsyncMock()
    mock_evaluate_host = AsyncMock()
    monkeypatch.setattr(correlation_worker, "add_event", mock_add_event)
    monkeypatch.setattr(correlation_worker, "evaluate_host", mock_evaluate_host)

    await correlation_worker._evaluate_correlation_async("does-not-exist")  # must not raise

    mock_add_event.assert_not_called()
    mock_evaluate_host.assert_not_called()


def test_evaluate_correlation_runs_the_async_flow_via_asyncio_run(monkeypatch):
    """The sync Celery entrypoint must actually drive _evaluate_correlation_async to completion."""
    calls = []

    async def _fake_async(alert_id):
        calls.append(alert_id)

    monkeypatch.setattr(correlation_worker, "_evaluate_correlation_async", _fake_async)

    correlation_worker.evaluate_correlation.run("xyz-789")

    assert calls == ["xyz-789"]


# ── Worker-shared engine reliability (SS-065 regression) ────────
#
# Same class of bug as tasks/scoring.py's own regression tests — see
# that module's comment. Observed live here specifically under a
# realistic burst of concurrent ingestion (SS-065's demo mode): without
# this, correlation tasks failed with "attached to a different loop".

@pytest.mark.asyncio
async def test_uses_the_nullpool_worker_session_factory_when_a_chain_is_detected(monkeypatch):
    """
    Replaces three former dispose-ordering tests. The shared pooled
    engine used to hand this task a connection created under a previous
    task's event loop, which then hung on BEGIN and stranded the
    Postgres backend; worker_session_factory (NullPool) makes that
    impossible. See tests/test_worker_db_lifecycle.py for the
    behavioural proof, and db/postgresql.py for the reasoning.
    """
    tenant_id = uuid.uuid4()
    doc = {
        "alert_id": "abc-123",
        "tenant_id": str(tenant_id),
        "host_id": "DESKTOP-042",
        "log_type": "authentication",
        "action": "failed_login",
        "severity": "low",
    }
    chain = DetectedChain(
        pattern=CorrelationPattern.CREDENTIAL_BRUTE_FORCE,
        confidence=0.8,
        alert_ids=("a1", "a2"),
        mitre_technique_ids=("T1110",),
        mitre_tactic="Credential Access",
    )
    monkeypatch.setattr(correlation_worker, "get_alert_by_id", AsyncMock(return_value=doc))
    monkeypatch.setattr(correlation_worker, "add_event", AsyncMock())
    monkeypatch.setattr(correlation_worker, "evaluate_host", AsyncMock(return_value=[chain]))
    monkeypatch.setattr(correlation_worker, "create_or_merge_incident", AsyncMock(return_value=Mock(id=uuid.uuid4())))
    monkeypatch.setattr(correlation_worker, "notify_attack_chain", AsyncMock())
    monkeypatch.setattr(correlation_worker, "publish_event", AsyncMock())
    monkeypatch.setattr(correlation_worker.soar_service, "evaluate_triggers", AsyncMock(return_value=None))
    used = []
    monkeypatch.setattr(correlation_worker, "worker_session_factory", lambda: used.append(1) or _FakeSessionCM())

    await correlation_worker._evaluate_correlation_async("abc-123")

    assert used, "the task must obtain its session from the worker factory"


@pytest.mark.asyncio
async def test_opens_no_database_session_when_no_chain_is_detected(monkeypatch):
    """Correlation runs once per alert; most alerts detect nothing and must never touch Postgres."""
    doc = {
        "alert_id": "abc-123",
        "tenant_id": str(uuid.uuid4()),
        "host_id": "DESKTOP-042",
        "log_type": "authentication",
        "action": "failed_login",
        "severity": "low",
    }
    monkeypatch.setattr(correlation_worker, "get_alert_by_id", AsyncMock(return_value=doc))
    monkeypatch.setattr(correlation_worker, "add_event", AsyncMock())
    monkeypatch.setattr(correlation_worker, "evaluate_host", AsyncMock(return_value=[]))
    used = []
    monkeypatch.setattr(correlation_worker, "worker_session_factory", lambda: used.append(1) or _FakeSessionCM())

    await correlation_worker._evaluate_correlation_async("abc-123")

    assert not used, "no chain detected — no session should have been opened"


