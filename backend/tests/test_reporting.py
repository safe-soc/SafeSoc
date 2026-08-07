"""
SafeSOC — Reporting Service Tests (SS-052)
Data gathering and HTML rendering are tested directly — the actual
WeasyPrint PDF-writing call (_write_pdf) is mocked everywhere here,
since it needs a native library (Pango) this dev environment doesn't
have installed; see reporting.py's module docstring. A real, unmocked
PDF is produced and verified via Docker (see the batch report).
"""

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest

from app.core.enums import IncidentStatus, RiskLevel
from app.models.endpoint import Endpoint
from app.models.incident import Incident
from app.models.tenant import Tenant
from app.services import reporting
from app.services.reporting import ReportData, _build_recommendations, _report_filename, render_report_html


def _incident(status=IncidentStatus.OPEN, alert_ids=None, created_at=None) -> Incident:
    return Incident(
        id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        status=status,
        alert_ids=alert_ids or ["a1"],
        created_at=created_at or datetime.now(timezone.utc),
    )


def _endpoint(host_id="DESKTOP-042", risk_score=80, risk_level=RiskLevel.HIGH) -> Endpoint:
    return Endpoint(
        id=uuid.uuid4(), tenant_id=uuid.uuid4(), host_id=host_id, risk_score=risk_score, risk_level=risk_level
    )


def _report_data(**overrides) -> ReportData:
    base = dict(
        tenant_name="Acme Corp",
        period_start=datetime(2026, 8, 1, tzinfo=timezone.utc),
        period_end=datetime(2026, 8, 8, tzinfo=timezone.utc),
        alerts_total=0,
        alerts_by_severity={},
        incidents=[],
        top_risk_endpoints=[],
        ti_malicious_count=0,
        cloud_summary={},
        recommendations=["No significant security events were recorded this period. Continue routine monitoring."],
    )
    base.update(overrides)
    return ReportData(**base)


# ── _build_recommendations ──────────────────────────────────────

def test_recommends_reviewing_critical_alerts():
    recs = _build_recommendations({"critical": 3}, [], [], 0, {})
    assert any("3 critical-severity alert" in r for r in recs)


def test_recommends_prioritizing_high_severity_alerts():
    recs = _build_recommendations({"high": 5}, [], [], 0, {})
    assert any("5 high-severity alert" in r for r in recs)


def test_recommends_assigning_open_incidents():
    incidents = [_incident(status=IncidentStatus.OPEN), _incident(status=IncidentStatus.RESOLVED)]
    recs = _build_recommendations({}, incidents, [], 0, {})
    assert any("1 incident(s) remain open" in r for r in recs)


def test_recommends_investigating_the_top_risk_endpoint_when_high_or_critical():
    endpoints = [_endpoint(host_id="DESKTOP-999", risk_score=90, risk_level=RiskLevel.CRITICAL)]
    recs = _build_recommendations({}, [], endpoints, 0, {})
    assert any("DESKTOP-999" in r for r in recs)


def test_does_not_flag_a_low_risk_top_endpoint():
    endpoints = [_endpoint(host_id="DESKTOP-001", risk_score=5, risk_level=RiskLevel.LOW)]
    recs = _build_recommendations({}, [], endpoints, 0, {})
    assert not any("DESKTOP-001" in r for r in recs)


def test_recommends_reviewing_ti_malicious_matches():
    recs = _build_recommendations({}, [], [], 4, {})
    assert any("4 alert(s) matched" in r for r in recs)


def test_recommends_reviewing_cloud_findings():
    recs = _build_recommendations({}, [], [], 0, {"total": 7})
    assert any("7 cloud security finding" in r for r in recs)


def test_falls_back_to_a_quiet_period_message_when_nothing_is_notable():
    recs = _build_recommendations({}, [], [], 0, {})
    assert recs == ["No significant security events were recorded this period. Continue routine monitoring."]


# ── render_report_html ──────────────────────────────────────────

def test_render_report_html_includes_tenant_name_and_period():
    data = _report_data(tenant_name="Acme Corp")
    output = render_report_html(data)

    assert "Acme Corp" in output
    assert "2026-08-01" in output
    assert "2026-08-08" in output


def test_render_report_html_empty_state_has_no_crash_and_sensible_text():
    """AC: a tenant with zero incidents/alerts renders gracefully, not an empty/broken table."""
    data = _report_data()
    output = render_report_html(data)

    assert "No alerts were recorded" in output
    assert "No incidents were opened" in output
    assert "No endpoints have been scored" in output


def test_render_report_html_lists_alert_severities():
    data = _report_data(alerts_total=5, alerts_by_severity={"critical": 2, "low": 3})
    output = render_report_html(data)

    assert "Critical" in output
    assert "Low" in output


def test_render_report_html_lists_incidents_and_endpoints():
    incident = _incident(status=IncidentStatus.INVESTIGATING, alert_ids=["a1", "a2"])
    endpoint = _endpoint(host_id="DESKTOP-777")
    data = _report_data(incidents=[incident], top_risk_endpoints=[endpoint])

    output = render_report_html(data)

    assert "Investigating" in output
    assert "DESKTOP-777" in output


def test_render_report_html_escapes_untrusted_tenant_name():
    """tenant_name is user-controlled (set at registration) — must not break out of the HTML structure."""
    data = _report_data(tenant_name="<script>alert(1)</script>")
    output = render_report_html(data)

    assert "<script>alert(1)</script>" not in output
    assert "&lt;script&gt;" in output


# ── _report_filename ─────────────────────────────────────────────

def test_report_filename_is_a_sortable_timestamp():
    generated_at = datetime(2026, 8, 7, 14, 30, 15, tzinfo=timezone.utc)
    assert _report_filename(generated_at) == "20260807T143015Z.pdf"


# ── gather_report_data (orchestration) ──────────────────────────

@pytest.mark.asyncio
async def test_gather_report_data_aggregates_alerts_incidents_endpoints_and_cloud(monkeypatch):
    tenant_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    monkeypatch.setattr(reporting, "_get_tenant_name", AsyncMock(return_value="Acme Corp"))
    monkeypatch.setattr(
        reporting,
        "search_alerts",
        AsyncMock(
            return_value={
                "total": 3,
                "alerts": [
                    {"severity": "critical", "ti_result": {"is_malicious": True}},
                    {"severity": "critical", "ti_result": None},
                    {"severity": "low", "ti_result": {"is_malicious": False}},
                ],
            }
        ),
    )
    in_period_incident = _incident(created_at=now)
    out_of_period_incident = _incident(created_at=now - timedelta(days=30))
    monkeypatch.setattr(
        reporting, "list_incidents", AsyncMock(return_value=([in_period_incident, out_of_period_incident], 2))
    )
    endpoints = [_endpoint(host_id=f"HOST-{i}") for i in range(15)]
    monkeypatch.setattr(reporting, "list_endpoints", AsyncMock(return_value=endpoints))
    monkeypatch.setattr(
        reporting, "get_cloud_summary", AsyncMock(return_value={"total": 2, "distinct_affected_resources": 1})
    )

    data = await reporting.gather_report_data(object(), tenant_id, days=7)

    assert data.tenant_name == "Acme Corp"
    assert data.alerts_total == 3
    assert data.alerts_by_severity == {"critical": 2, "low": 1}
    assert data.ti_malicious_count == 1
    assert data.incidents == [in_period_incident]  # the 30-day-old one is filtered out
    assert len(data.top_risk_endpoints) == reporting.TOP_RISK_ENDPOINT_LIMIT  # sliced to the top 10 of 15
    assert data.cloud_summary == {"total": 2, "distinct_affected_resources": 1}
    assert data.recommendations  # non-empty: critical alerts alone guarantee at least one


@pytest.mark.asyncio
async def test_get_tenant_name_falls_back_to_the_id_when_the_tenant_row_is_missing():
    class _FakeResult:
        def scalar_one_or_none(self):
            return None

    class _FakeSession:
        async def execute(self, stmt):
            return _FakeResult()

    tenant_id = uuid.uuid4()
    name = await reporting._get_tenant_name(_FakeSession(), tenant_id)

    assert name == str(tenant_id)


@pytest.mark.asyncio
async def test_get_tenant_name_returns_the_real_name_when_found():
    tenant = Tenant(id=uuid.uuid4(), name="Acme Corp")

    class _FakeResult:
        def scalar_one_or_none(self):
            return tenant

    class _FakeSession:
        async def execute(self, stmt):
            return _FakeResult()

    name = await reporting._get_tenant_name(_FakeSession(), tenant.id)

    assert name == "Acme Corp"


# ── generate_report (top-level orchestration, PDF write mocked) ─

@pytest.mark.asyncio
async def test_generate_report_saves_under_a_tenant_scoped_directory(monkeypatch, tmp_path):
    tenant_id = uuid.uuid4()
    monkeypatch.setattr(reporting, "gather_report_data", AsyncMock(return_value=_report_data()))
    # _write_pdf is sync in the real module — a plain Mock, not AsyncMock, to match its call signature.
    from unittest.mock import Mock
    mock_write_pdf = Mock()
    monkeypatch.setattr(reporting, "_write_pdf", mock_write_pdf)

    result_path = await reporting.generate_report(object(), tenant_id, days=7, output_dir=tmp_path)

    assert result_path.parent == tmp_path / str(tenant_id)
    assert result_path.suffix == ".pdf"
    mock_write_pdf.assert_called_once()
    called_html, called_path = mock_write_pdf.call_args[0]
    assert called_path == result_path
    assert "<html>" in called_html
