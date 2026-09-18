"""
SafeSOC — Investigation Report Renderer Tests
render_investigation_report_html() is pure (string in, string out) --
no WeasyPrint/DB/OpenSearch involved -- so it's tested directly here,
both for a fully-populated scope (every section has real content) and
an entirely empty one (AC: a scope with no evidence yet must still
render clean "no data" states, never crash or show a broken/empty
template).
"""

from datetime import datetime, timezone

from app.services.investigation_report import (
    AlertRow,
    AppendixData,
    AttackChainData,
    BehaviorFinding,
    DailyCount,
    EndpointAnalysis,
    ExecutiveSummary,
    InvestigationFindings,
    InvestigationQA,
    InvestigationReportData,
    KeyFinding,
    MitreRow,
    NetworkRow,
    Recommendation,
    Recommendations,
    ReportMetadata,
    SeverityCounts,
    SoftwareData,
    Statistics,
    TimelineEvent,
    UserActivity,
    VulnerabilityRow,
)
from app.services.investigation_report_render import (
    _daily_volume_chart,
    _finish_sentence,
    _severity_badge,
    render_investigation_report_html,
)


def _empty_report_data(scope_type="incident", is_synthetic=False):
    metadata = ReportMetadata(
        report_id="11111111-1111-1111-1111-111111111111", scope_type=scope_type, scope_name="d3b4fb53",
        tenant_name="Acme Corp", generated_at=datetime(2026, 8, 26, 17, 0, 0, tzinfo=timezone.utc),
        risk_score=None, risk_level=None, is_synthetic=is_synthetic,
    )
    summary = ExecutiveSummary(
        verdict="Low — no significant activity observed.", severity="low", investigation_status="open",
        first_observed=None, last_observed=None, affected_endpoints=0, affected_users=0, alert_count=0,
        incident_count=0, critical_high_alert_count=0, narrative="No notable activity.", narrative_is_fallback=True,
        key_findings=[],
    )
    return _report_data_from(metadata, summary)


def _report_data_from(metadata, summary):
    return InvestigationReportData(
        metadata=metadata, summary=summary,
        statistics=Statistics(severity=SeverityCounts(), alerts_over_time=[], affected_hosts=0, affected_users=0),
        timeline=[], attack_chain=None, behavior_findings=[], alerts=[], alerts_total=0, endpoints=[], users=[],
        software=SoftwareData(rows=[], has_any_software=False, has_any_synthetic_vuln=False, has_any_real_vuln=False),
        mitre=[], network=[],
        investigation=InvestigationFindings(qa=[], narrative="", narrative_is_fallback=True, has_data=False),
        recommendations=Recommendations(immediate=[], investigation=[], containment=[], long_term=[]),
        appendix=AppendixData(incident_ids=[], endpoint_ids=[], user_ids=[], mitre_technique_ids=[], evidence_alert_count=0),
    )


def _populated_report_data():
    metadata = ReportMetadata(
        report_id="22222222-2222-2222-2222-222222222222", scope_type="incident", scope_name="d3b4fb53",
        tenant_name="<Acme> & Co", generated_at=datetime(2026, 8, 26, 17, 0, 0, tzinfo=timezone.utc),
        risk_score=None, risk_level="critical", is_synthetic=True,
    )
    summary = ExecutiveSummary(
        verdict="Critical — confirmed high-impact security activity requiring immediate response.",
        severity="critical", investigation_status="open",
        first_observed=datetime(2026, 8, 26, 9, 0, tzinfo=timezone.utc),
        last_observed=datetime(2026, 8, 26, 10, 0, tzinfo=timezone.utc),
        affected_endpoints=1, affected_users=1, alert_count=8, incident_count=1, critical_high_alert_count=1,
        narrative="Suspicious activity was observed on the affected host, and it continued for some time before it",  # deliberately unterminated
        narrative_is_fallback=False, key_findings=[KeyFinding("1 critical-severity alert(s) were recorded.")],
    )
    ts = datetime(2026, 8, 26, 9, 0, tzinfo=timezone.utc)

    endpoint = EndpointAnalysis(
        host_id="DEMO-CRITICAL-01", risk_score=100, risk_level="critical",
        severity=SeverityCounts(critical=1, high=0, medium=0, low=7), after_hours_count=0,
        associated_incident_ids=["d3b4fb53-488f-4306-91d9-232582b67860"], risk_factors=["1 critical-severity alert(s)"],
    )
    user = UserActivity(
        user="leo.chen", host_count=1, alert_count=8, failed_logins=6, successful_logins=1, after_hours_count=0,
        associated_incident_ids=["d3b4fb53-488f-4306-91d9-232582b67860"],
    )
    software = SoftwareData(
        rows=[
            VulnerabilityRow(software="Zoom", version="5.16.2", host_id="DEMO-CRITICAL-01", vulnerability_id=None, severity=None, title=None, is_synthetic=None),
            VulnerabilityRow(software="OldApp", version="1.0", host_id="DEMO-CRITICAL-01", vulnerability_id="DEMO-VULN-0001", severity="high", title="Demo finding", is_synthetic=True),
        ],
        has_any_software=True, has_any_synthetic_vuln=True, has_any_real_vuln=False,
    )
    attack_chain = AttackChainData(
        nodes=[], edges=[], grouped_edges=[], node_positions={}, progression=["DEMO-CRITICAL-01", "leo.chen"],
    )
    return InvestigationReportData(
        metadata=metadata, summary=summary, statistics=Statistics(
            severity=SeverityCounts(critical=1, high=0, medium=0, low=7),
            alerts_over_time=[DailyCount(date="2026-08-26", count=8)], affected_hosts=1, affected_users=1,
        ),
        timeline=[TimelineEvent(timestamp=ts, event_type="Failed Login", host="DEMO-CRITICAL-01", user="leo.chen", severity="low", reference="abc123", description="Failed login attempt")],
        attack_chain=attack_chain,
        behavior_findings=[BehaviorFinding(category="Credential attacks", severity="low", description="6 event(s) matching credential attacks.", affected_asset="DEMO-CRITICAL-01", affected_user="leo.chen", evidence_count=6, first_seen=ts, last_seen=ts)],
        alerts=[AlertRow(timestamp=ts, alert_id=str("ceed412b-0000-0000-0000-000000000000"), severity="critical", log_type="privilege", host_id="DEMO-CRITICAL-01", user="leo.chen", description="Privilege escalation detected", mitre_technique="T1068", status="new")],
        alerts_total=8, endpoints=[endpoint], users=[user], software=software,
        mitre=[MitreRow(technique_id="T1068", tactic="Privilege Escalation", evidence_description="Privilege escalation detected", affected_host="DEMO-CRITICAL-01", related_alert="ceed412b")],
        network=[NetworkRow(source_host="DEMO-CRITICAL-01", destination_ip="192.168.10.134", port=None, protocol=None, event_count=2, classification="Not checked")],
        investigation=InvestigationFindings(qa=[InvestigationQA(question="Is this host compromised?", answer="Evidence insufficient to determine this.", is_fallback=False)], narrative="", narrative_is_fallback=False, has_data=True),
        recommendations=Recommendations(
            immediate=[Recommendation(observed="1 critical-severity alert(s) were recorded.", recommended="Isolate the affected host(s) immediately.")],
            investigation=[], containment=[], long_term=["Continue monitoring."],
        ),
        appendix=AppendixData(incident_ids=["d3b4fb53-488f-4306-91d9-232582b67860"], endpoint_ids=["DEMO-CRITICAL-01"], user_ids=["leo.chen"], mitre_technique_ids=["T1068"], evidence_alert_count=8),
    )


# ── full-document smoke tests ─────────────────────────────────────

def test_render_investigation_report_html_empty_scope_has_no_crash_and_clean_empty_states():
    output = render_investigation_report_html(_empty_report_data())

    assert "<!doctype html>" in output
    assert "Security Investigation Report" in output
    assert "No relationship graph could be derived" in output  # attack_chain=None
    assert "No alerts are present in this scope" in output
    assert "No endpoints are present in this scope" in output
    assert "No software inventory data available" in output
    assert "No MITRE ATT&amp;CK techniques are associated" in output
    assert "No network destination telemetry" in output
    assert "Evidence insufficient to determine this." in output  # investigation.has_data=False


def test_render_investigation_report_html_populated_scope_includes_every_section_title():
    output = render_investigation_report_html(_populated_report_data())

    for title in (
        "Executive Summary", "Incident Overview", "Security Activity Summary", "Investigation Timeline",
        "Attack Chain", "Behavior / Security Findings", "Alert Evidence", "Endpoint Analysis",
        "Users and Identity Activity", "Software &amp; Vulnerabilities", "MITRE ATT&amp;CK Mapping",
        "Network / Communication Activity", "Investigation / AI Analyst Findings", "Response / Recommendations",
        "Appendix / Evidence Summary",
    ):
        assert title in output, f"missing section: {title}"


def test_render_investigation_report_html_marks_synthetic_data_on_cover_and_appendix():
    output = render_investigation_report_html(_populated_report_data())
    assert "SYNTHETIC DEMONSTRATION DATA" in output
    assert "does not represent a real organization" in output


def test_render_investigation_report_html_escapes_untrusted_scope_name_on_the_cover_page():
    """scope_name (an incident/host id) is echoed on the cover page -- must not break out of the HTML."""
    import dataclasses

    data = _populated_report_data()
    unsafe_data = dataclasses.replace(data, metadata=dataclasses.replace(data.metadata, scope_name="<script>alert(1)</script>"))

    output = render_investigation_report_html(unsafe_data)

    assert "<script>alert(1)</script>" not in output
    assert "&lt;script&gt;" in output


def test_render_investigation_report_html_includes_investigation_session_qa_verbatim():
    output = render_investigation_report_html(_populated_report_data())
    assert "Is this host compromised?" in output
    assert "Evidence insufficient to determine this." in output


def test_render_investigation_report_html_alert_evidence_uses_landscape_page():
    """The 9-column Alert Evidence table needs the extra landscape width to avoid overflow/collapse (see _CSS)."""
    output = render_investigation_report_html(_populated_report_data())
    assert '<section class="content-section landscape">' in output
    assert "Alert Evidence" in output


# ── small render helpers ───────────────────────────────────────────

def test_finish_sentence_appends_ellipsis_only_when_not_already_terminated():
    assert _finish_sentence("this trails off mid") == "this trails off mid…"
    assert _finish_sentence("This is complete.") == "This is complete."


def test_severity_badge_defaults_to_low_for_missing_severity():
    assert "Low" in _severity_badge(None)


def test_daily_volume_chart_shows_a_visible_count_label_per_bar():
    """Regression: a single-day chart used to render as a count-less solid block (see module history)."""
    chart = _daily_volume_chart([DailyCount(date="2026-08-26", count=8)])
    assert '<span class="vol-bar-count">8</span>' in chart
