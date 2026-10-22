"""
SafeSOC — Investigation Report Data Tests
Direct unit tests for the pure computation helpers in
services/investigation_report.py, plus the top-level generate_*
orchestration functions with gather_*/​_write_pdf mocked (mirrors
tests/test_reporting.py's own pattern for the exact same reason:
_write_pdf needs WeasyPrint's native Pango library, which this dev
environment doesn't have installed).
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock

import pytest

from app.core.enums import CorrelationPattern
from app.schemas.incidents import TimelineEntry
from app.services import investigation_report as ir
from app.services.incident_graph import GraphEdge


def _alert(**overrides) -> dict:
    base = {
        "alert_id": str(uuid.uuid4()),
        "timestamp": "2026-08-20T09:00:00Z",
        "severity": "low",
        "log_type": "authentication",
        "action": "failed_login",
        "host_id": "DESKTOP-042",
        "user": "leo.chen",
        "description": "Failed login attempt",
        "status": "new",
    }
    base.update(overrides)
    return base


# ── _severity_counts / _daily_counts ──────────────────────────────

def test_severity_counts_tallies_known_severities_only():
    alerts = [_alert(severity="critical"), _alert(severity="critical"), _alert(severity="unknown-value")]
    counts = ir._severity_counts(alerts)
    assert counts.critical == 2
    assert counts.total == 2


def test_daily_counts_buckets_by_calendar_day_and_sorts_chronologically():
    alerts = [
        _alert(timestamp="2026-08-21T01:00:00Z"),
        _alert(timestamp="2026-08-20T23:00:00Z"),
        _alert(timestamp="2026-08-20T01:00:00Z"),
    ]
    daily = ir._daily_counts(alerts)
    assert [d.date for d in daily] == ["2026-08-20", "2026-08-21"]
    assert daily[0].count == 2


# ── _is_after_hours ────────────────────────────────────────────────

def test_is_after_hours_true_on_weekend():
    saturday = datetime(2026, 8, 22, 12, 0, tzinfo=timezone.utc)  # a Saturday
    assert ir._is_after_hours(saturday) is True


def test_is_after_hours_false_during_a_weekday_business_hour():
    weekday_business_hour = datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc)  # a Monday
    assert ir._is_after_hours(weekday_business_hour) is False


# ── _behavior_findings ────────────────────────────────────────────

def test_behavior_findings_only_includes_categories_with_matching_evidence():
    alerts = [_alert(action="failed_login")]
    findings = ir._behavior_findings(alerts)
    categories = {f.category for f in findings}
    assert "Credential attacks" in categories
    assert "Privilege escalation" not in categories


def test_behavior_findings_includes_after_hours_category_separately():
    saturday_alert = _alert(action="failed_login", timestamp="2026-08-22T12:00:00Z")
    findings = ir._behavior_findings([saturday_alert])
    categories = {f.category for f in findings}
    assert "After-hours activity" in categories
    assert "Credential attacks" in categories


# ── _mitre_rows ────────────────────────────────────────────────────

def test_mitre_rows_deduplicates_by_technique_and_host():
    alerts = [
        _alert(mitre_technique="T1078", host_id="HOST-A"),
        _alert(mitre_technique="T1078", host_id="HOST-A"),  # duplicate, same (technique, host)
        _alert(mitre_technique="T1078", host_id="HOST-B"),
        _alert(mitre_technique=None),
    ]
    rows = ir._mitre_rows(alerts)
    assert len(rows) == 2
    assert {r.affected_host for r in rows} == {"HOST-A", "HOST-B"}


def test_mitre_rows_splits_a_comma_joined_technique_value_into_separate_rows():
    """adapters/wazuh.py stores several ids in one string — each is its own technique, not one row."""
    rows = ir._mitre_rows([_alert(mitre_technique="T1110.001, T1021.004", host_id="HOST-A")])

    assert [r.technique_id for r in rows] == ["T1021.004", "T1110.001"]
    assert {r.affected_host for r in rows} == {"HOST-A"}


def test_mitre_rows_adds_a_row_for_the_incident_categorys_mapped_techniques():
    """The pattern-level source: a synthetic incident whose alerts carry no MITRE still reports its category's techniques."""
    alerts = [_alert(mitre_technique=None, host_id="HOST-B"), _alert(mitre_technique=None, host_id="HOST-A")]

    rows = ir._mitre_rows(alerts, CorrelationPattern.SUCCESSFUL_COMPROMISE)

    assert [r.technique_id for r in rows] == ["T1078", "T1110"]
    assert all(r.tactic == "Initial Access" for r in rows)
    assert all(r.evidence_description == "Detected correlation pattern: successful compromise" for r in rows)
    assert all(r.affected_host == "HOST-A, HOST-B" for r in rows)
    assert all(r.related_alert == "—" for r in rows)


def test_mitre_rows_does_not_duplicate_a_category_technique_the_alerts_already_cover():
    rows = ir._mitre_rows(
        [_alert(mitre_technique="T1110", host_id="HOST-A")], CorrelationPattern.CREDENTIAL_BRUTE_FORCE
    )

    assert [r.technique_id for r in rows] == ["T1110"]
    assert rows[0].related_alert != "—"


def test_behavior_findings_match_privilege_escalation_on_either_mapped_technique():
    """T1548 replaced T1068 in the pattern mapping, and both must still be recognized here."""
    for technique in ("T1068", "T1548"):
        findings = ir._behavior_findings([_alert(action="permission_change", mitre_technique=technique)])
        assert "Privilege escalation" in {f.category for f in findings}, technique


def test_behavior_findings_match_lateral_movement_on_a_sub_technique():
    """A comma-joined sub-technique (T1021.004) belongs to its parent T1021."""
    findings = ir._behavior_findings([_alert(action="remote_login", mitre_technique="T1110.001, T1021.004")])

    assert "Lateral movement" in {f.category for f in findings}


# ── _network_rows ──────────────────────────────────────────────────

def test_network_rows_classifies_malicious_over_clean_over_not_checked():
    malicious = _alert(destination_ip="1.2.3.4", ti_result={"is_malicious": True})
    clean = _alert(destination_ip="5.6.7.8", ti_result={"is_malicious": False})
    unchecked = _alert(destination_ip="9.9.9.9", ti_result=None)
    rows = ir._network_rows([malicious, clean, unchecked])
    by_ip = {r.destination_ip: r.classification for r in rows}
    assert by_ip["1.2.3.4"] == "Malicious"
    assert by_ip["5.6.7.8"] == "Clean"
    assert by_ip["9.9.9.9"] == "Not checked"


def test_network_rows_skips_alerts_with_no_destination_ip():
    assert ir._network_rows([_alert()]) == []


# ── _group_parallel_edges / _compute_force_layout (graphLayout.ts port) ──

def _edge(source, target, mitre=None) -> GraphEdge:
    return GraphEdge(source=source, target=target, alert_id=str(uuid.uuid4()), timestamp=datetime.now(timezone.utc), mitre_technique=mitre)


def test_group_parallel_edges_groups_by_unordered_entity_pair():
    edges = [_edge("host-1", "user-1"), _edge("user-1", "host-1"), _edge("host-1", "user-2")]
    grouped = ir._group_parallel_edges(edges)
    assert len(grouped) == 2
    pair = next(g for g in grouped if {g.source_id, g.target_id} == {"host-1", "user-1"})
    assert pair.count == 2


def test_compute_force_layout_is_deterministic_and_places_every_node():
    node_ids = ["host-1", "user-1", "user-2"]
    edges = ir._group_parallel_edges([_edge("host-1", "user-1"), _edge("host-1", "user-2")])

    layout_a = ir._compute_force_layout(node_ids, edges, 700, 420)
    layout_b = ir._compute_force_layout(node_ids, edges, 700, 420)

    assert layout_a == layout_b  # same seed/algorithm every time -> identical output
    assert set(layout_a.keys()) == set(node_ids)
    for x, y in layout_a.values():
        assert 0 <= x <= 700
        assert 0 <= y <= 420


# ── _verdict ───────────────────────────────────────────────────────

def test_verdict_escalates_with_critical_alerts():
    from app.services.investigation_report import SeverityCounts
    assert "Critical" in ir._verdict(SeverityCounts(critical=1), behavior_count=0)


def test_verdict_is_calm_when_nothing_stands_out():
    from app.services.investigation_report import SeverityCounts
    verdict = ir._verdict(SeverityCounts(low=1), behavior_count=0)
    assert "Critical" not in verdict
    assert "High" not in verdict


# ── _timeline_events (regression: SS-1xx report-timeline bloat fix) ──
# Real incidents can accumulate dozens of near-identical "Incident
# Merged" audit rows as the correlation engine re-evaluates the same
# incident tenant-wide. Before this fix, each one was rendered
# verbatim -- including a raw Python list repr of chain_alert_ids --
# which could balloon the report's timeline section to 8+ pages of
# noise. These tests pin the fix: audit rows collapse by
# (event_type, formatted description), and list-valued details are
# summarized as a count, never dumped verbatim.

def test_timeline_events_summarizes_list_valued_audit_details_instead_of_dumping_them():
    entry = TimelineEntry(
        type="audit", timestamp=datetime(2026, 8, 26, 16, 16, 19, tzinfo=timezone.utc),
        data={"action": "incident.merged", "actor_user_id": None, "details": {"chain_alert_ids": [str(uuid.uuid4()) for _ in range(6)], "pattern": "credential_brute_force"}},
    )
    events = ir._timeline_events([entry])
    assert len(events) == 1
    assert "6 item(s)" in events[0].description
    assert "chain_alert_ids: [" not in events[0].description  # never a raw list repr


def test_timeline_events_collapses_repeated_identical_audit_entries_with_a_count():
    make = lambda minute: TimelineEntry(
        type="audit", timestamp=datetime(2026, 8, 26, 16, 16, minute, tzinfo=timezone.utc),
        data={"action": "incident.merged", "actor_user_id": None, "details": {"pattern": "privilege_escalation", "confidence": 0.95}},
    )
    entries = [make(19), make(21), make(37)]

    events = ir._timeline_events(entries)

    assert len(events) == 1  # three identical audit rows collapse into one
    assert "recurred 3×" in events[0].description
    assert events[0].timestamp == datetime(2026, 8, 26, 16, 16, 19, tzinfo=timezone.utc)  # anchored at the first occurrence


def test_timeline_events_does_not_collapse_distinct_audit_entries():
    merged = TimelineEntry(
        type="audit", timestamp=datetime(2026, 8, 26, 16, 16, 19, tzinfo=timezone.utc),
        data={"action": "incident.merged", "actor_user_id": None, "details": {"pattern": "a"}},
    )
    transitioned = TimelineEntry(
        type="audit", timestamp=datetime(2026, 8, 26, 16, 20, 0, tzinfo=timezone.utc),
        data={"action": "incident.transitioned", "actor_user_id": None, "details": {"to_status": "investigating"}},
    )
    events = ir._timeline_events([merged, transitioned])
    assert len(events) == 2


def test_timeline_events_keeps_alert_and_note_entries_uncollapsed_and_sorted():
    alert_entry = TimelineEntry(type="alert", timestamp=datetime(2026, 8, 26, 9, 0, tzinfo=timezone.utc), data=_alert())
    note_entry = TimelineEntry(
        type="note", timestamp=datetime(2026, 8, 26, 8, 0, tzinfo=timezone.utc),
        data={"author_user_id": str(uuid.uuid4()), "body": "Looks suspicious."},
    )
    events = ir._timeline_events([alert_entry, note_entry])
    assert [e.event_type for e in events] == ["Analyst Note", "Failed Login"]  # sorted chronologically


# ── _slugify / _investigation_report_filename ─────────────────────

def test_slugify_strips_unsafe_filename_characters():
    assert ir._slugify("DEMO/CRITICAL:01?") == "DEMO-CRITICAL-01"


def test_investigation_report_filename_is_prefixed_and_sortable():
    generated_at = datetime(2026, 8, 26, 17, 5, 4, tzinfo=timezone.utc)
    filename = ir._investigation_report_filename("endpoint", "DEMO-CRITICAL-01", generated_at)
    assert filename == "investigation-endpoint-DEMO-CRITICAL-01-20260826T170504Z.pdf"


# ── generate_incident_report / generate_endpoint_report (PDF write mocked) ──

@pytest.mark.asyncio
async def test_generate_incident_report_saves_under_a_tenant_scoped_directory(monkeypatch, tmp_path):
    tenant_id = uuid.uuid4()
    incident_id = uuid.uuid4()
    fake_data = Mock()
    fake_data.metadata.generated_at = datetime(2026, 8, 26, 17, 5, 4, tzinfo=timezone.utc)
    monkeypatch.setattr(ir, "gather_incident_report_data", AsyncMock(return_value=fake_data))
    monkeypatch.setattr("app.services.investigation_report_render.render_investigation_report_html", Mock(return_value="<html></html>"))
    mock_write_pdf = Mock()
    monkeypatch.setattr(ir, "_write_pdf", mock_write_pdf)

    result_path, generated_at = await ir.generate_incident_report(object(), tenant_id, incident_id, output_dir=tmp_path)

    assert result_path.parent == tmp_path / str(tenant_id)
    assert result_path.name.startswith("investigation-incident-")
    assert generated_at == fake_data.metadata.generated_at
    mock_write_pdf.assert_called_once()


@pytest.mark.asyncio
async def test_generate_endpoint_report_saves_under_a_tenant_scoped_directory(monkeypatch, tmp_path):
    tenant_id = uuid.uuid4()
    fake_data = Mock()
    fake_data.metadata.generated_at = datetime(2026, 8, 26, 17, 5, 4, tzinfo=timezone.utc)
    monkeypatch.setattr(ir, "gather_endpoint_report_data", AsyncMock(return_value=fake_data))
    monkeypatch.setattr("app.services.investigation_report_render.render_investigation_report_html", Mock(return_value="<html></html>"))
    mock_write_pdf = Mock()
    monkeypatch.setattr(ir, "_write_pdf", mock_write_pdf)

    result_path, generated_at = await ir.generate_endpoint_report(object(), tenant_id, "DEMO-CRITICAL-01", output_dir=tmp_path)

    assert result_path.parent == tmp_path / str(tenant_id)
    assert result_path.name == "investigation-endpoint-DEMO-CRITICAL-01-20260826T170504Z.pdf"
    assert generated_at == fake_data.metadata.generated_at
    mock_write_pdf.assert_called_once()
