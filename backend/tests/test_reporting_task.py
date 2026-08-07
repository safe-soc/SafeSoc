"""
SafeSOC — Scheduled Weekly Report Task Tests (SS-053)
"""

import uuid
from unittest.mock import AsyncMock

import pytest

from app.models.tenant import Tenant
from app.tasks import reporting as reporting_task


class _FakeSessionCM:
    async def __aenter__(self):
        return "fake-db-session"

    async def __aexit__(self, *args):
        return False


def _tenant(name="Acme Corp") -> Tenant:
    return Tenant(id=uuid.uuid4(), name=name)


@pytest.mark.asyncio
async def test_generates_one_report_per_known_tenant(monkeypatch):
    tenant_a, tenant_b = _tenant("Acme Corp"), _tenant("Globex Inc")
    monkeypatch.setattr(reporting_task, "_list_tenants", AsyncMock(return_value=[tenant_a, tenant_b]))
    monkeypatch.setattr(reporting_task, "async_session_factory", lambda: _FakeSessionCM())
    mock_generate_report = AsyncMock()
    monkeypatch.setattr(reporting_task, "generate_report", mock_generate_report)

    await reporting_task._generate_all_tenant_reports_async()

    assert mock_generate_report.call_count == 2
    mock_generate_report.assert_any_call("fake-db-session", tenant_a.id)
    mock_generate_report.assert_any_call("fake-db-session", tenant_b.id)


@pytest.mark.asyncio
async def test_no_ops_when_there_are_no_known_tenants(monkeypatch):
    monkeypatch.setattr(reporting_task, "_list_tenants", AsyncMock(return_value=[]))
    monkeypatch.setattr(reporting_task, "async_session_factory", lambda: _FakeSessionCM())
    mock_generate_report = AsyncMock()
    monkeypatch.setattr(reporting_task, "generate_report", mock_generate_report)

    await reporting_task._generate_all_tenant_reports_async()  # must not raise

    mock_generate_report.assert_not_called()


@pytest.mark.asyncio
async def test_one_tenants_failure_does_not_block_the_rest(monkeypatch):
    """AC: one report per tenant per scheduled run — a single tenant's failure must not skip the others."""
    tenant_a, tenant_b, tenant_c = _tenant("A"), _tenant("B"), _tenant("C")
    monkeypatch.setattr(reporting_task, "_list_tenants", AsyncMock(return_value=[tenant_a, tenant_b, tenant_c]))
    monkeypatch.setattr(reporting_task, "async_session_factory", lambda: _FakeSessionCM())

    async def _fail_for_b(db, tenant_id):
        if tenant_id == tenant_b.id:
            raise RuntimeError("weasyprint blew up")

    mock_generate_report = AsyncMock(side_effect=_fail_for_b)
    monkeypatch.setattr(reporting_task, "generate_report", mock_generate_report)

    await reporting_task._generate_all_tenant_reports_async()  # must not raise

    assert mock_generate_report.call_count == 3  # tried all three, despite B's failure


@pytest.mark.asyncio
async def test_generates_exactly_one_report_per_tenant_not_duplicated(monkeypatch):
    tenant = _tenant()
    monkeypatch.setattr(reporting_task, "_list_tenants", AsyncMock(return_value=[tenant]))
    monkeypatch.setattr(reporting_task, "async_session_factory", lambda: _FakeSessionCM())
    mock_generate_report = AsyncMock()
    monkeypatch.setattr(reporting_task, "generate_report", mock_generate_report)

    await reporting_task._generate_all_tenant_reports_async()

    mock_generate_report.assert_called_once_with("fake-db-session", tenant.id)


@pytest.mark.asyncio
async def test_disposes_the_engine_before_and_after_a_successful_run(monkeypatch):
    """Same worker-shared-engine reliability requirement as tasks/scoring.py — see that module's own regression test."""
    monkeypatch.setattr(reporting_task, "_list_tenants", AsyncMock(return_value=[]))
    monkeypatch.setattr(reporting_task, "async_session_factory", lambda: _FakeSessionCM())
    mock_engine = AsyncMock()
    monkeypatch.setattr(reporting_task, "engine", mock_engine)

    await reporting_task._generate_all_tenant_reports_async()

    assert mock_engine.dispose.call_count == 2


@pytest.mark.asyncio
async def test_disposes_the_engine_even_if_listing_tenants_raises(monkeypatch):
    monkeypatch.setattr(reporting_task, "_list_tenants", AsyncMock(side_effect=RuntimeError("postgres down")))
    monkeypatch.setattr(reporting_task, "async_session_factory", lambda: _FakeSessionCM())
    mock_engine = AsyncMock()
    monkeypatch.setattr(reporting_task, "engine", mock_engine)

    with pytest.raises(RuntimeError):
        await reporting_task._generate_all_tenant_reports_async()

    assert mock_engine.dispose.call_count == 2


def test_generate_all_tenant_reports_runs_the_async_flow_via_asyncio_run(monkeypatch):
    calls = []

    async def _fake_async():
        calls.append(True)

    monkeypatch.setattr(reporting_task, "_generate_all_tenant_reports_async", _fake_async)

    reporting_task.generate_all_tenant_reports.run()

    assert calls == [True]
