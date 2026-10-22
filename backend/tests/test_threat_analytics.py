"""
SafeSOC — Threat Analytics Rollup Service Tests (SS-111)
Real tenant/date-range SQL filtering (_category_counts' WHERE clause)
can't be meaningfully proven against a fake session that just hands
back a canned row list — same limitation acknowledged throughout this
test suite (see tests/test_incidents.py's own notes) — so that part is
verified live against Docker Postgres instead. These tests cover the
row-mapping shape and the full trend-computation logic (percentage
math, MITRE mapping, sorting) by mocking _category_counts directly.

The KPI/trend/status/severity/MITRE/affected-assets sections added
after the original trend rollup are covered separately below, by
mocking _current_window_incidents/get_alerts_by_ids/_endpoints_by_host
directly (same boundary-mocking approach) and by unit-testing the pure
_extract_signals/_kpis/_daily_trend/etc. helpers directly against
constructed incident/alert data.
"""

import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.core.enums import CorrelationPattern, IncidentStatus, RiskLevel, Severity
from app.models.endpoint import Endpoint
from app.services.threat_analytics import (
    _affected_assets,
    _category_counts,
    _daily_trend,
    _extract_signals,
    _kpis,
    _mitre_technique_counts,
    _severity_breakdown,
    _status_breakdown,
    _technique_ids,
    get_threat_analytics,
)


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _FakeSession:
    def __init__(self, rows):
        self._rows = rows

    async def execute(self, stmt, params=None):
        return _FakeResult(self._rows)


def _mock_category_counts(monkeypatch, current: dict, previous: dict):
    mock = AsyncMock(side_effect=[current, previous])
    monkeypatch.setattr("app.services.threat_analytics._category_counts", mock)
    return mock


@pytest.fixture(autouse=True)
def _mock_current_window_incidents(monkeypatch):
    """
    None of the pre-existing tests below exercise the newer KPI/trend/
    status/severity/MITRE/affected-assets sections (they only assert
    on `trends`/`window_days`) — default this to an empty window so
    get_threat_analytics' extra query doesn't need a real db session
    (several of these tests call it with db=None). Tests that DO want
    to exercise the new sections override this mock explicitly.
    """
    mock = AsyncMock(return_value=[])
    monkeypatch.setattr("app.services.threat_analytics._current_window_incidents", mock)
    return mock


# ── _category_counts row mapping ─────────────────────────────────────

@pytest.mark.asyncio
async def test_category_counts_maps_rows_to_a_dict():
    session = _FakeSession([(CorrelationPattern.CREDENTIAL_BRUTE_FORCE, 5), (CorrelationPattern.LATERAL_MOVEMENT, 2)])
    now = datetime.now(timezone.utc)

    result = await _category_counts(session, uuid.uuid4(), now, now)

    assert result == {CorrelationPattern.CREDENTIAL_BRUTE_FORCE: 5, CorrelationPattern.LATERAL_MOVEMENT: 2}


@pytest.mark.asyncio
async def test_category_counts_returns_empty_dict_for_no_rows():
    session = _FakeSession([])
    now = datetime.now(timezone.utc)

    result = await _category_counts(session, uuid.uuid4(), now, now)

    assert result == {}


# ── get_threat_analytics trend computation ───────────────────────────

@pytest.mark.asyncio
async def test_computes_percentage_change_between_windows(monkeypatch):
    _mock_category_counts(
        monkeypatch,
        {CorrelationPattern.CREDENTIAL_BRUTE_FORCE: 14},
        {CorrelationPattern.CREDENTIAL_BRUTE_FORCE: 10},
    )

    result = await get_threat_analytics(None, uuid.uuid4())

    trend = result.trends[0]
    assert trend.current_count == 14
    assert trend.previous_count == 10
    assert trend.change_pct == 40.0


@pytest.mark.asyncio
async def test_change_pct_is_none_when_previous_count_is_zero(monkeypatch):
    """Undefined percentage change, not infinite or zero, when there was nothing to compare against."""
    _mock_category_counts(monkeypatch, {CorrelationPattern.LATERAL_MOVEMENT: 3}, {})

    result = await get_threat_analytics(None, uuid.uuid4())

    trend = result.trends[0]
    assert trend.change_pct is None
    assert trend.current_count == 3
    assert trend.previous_count == 0


@pytest.mark.asyncio
async def test_a_category_that_stopped_appears_with_zero_current_count(monkeypatch):
    _mock_category_counts(monkeypatch, {}, {CorrelationPattern.DATA_EXFILTRATION: 5})

    result = await get_threat_analytics(None, uuid.uuid4())

    trend = result.trends[0]
    assert trend.category == CorrelationPattern.DATA_EXFILTRATION
    assert trend.current_count == 0
    assert trend.previous_count == 5
    assert trend.change_pct == -100.0


@pytest.mark.asyncio
async def test_includes_mitre_tactic_and_technique_ids(monkeypatch):
    _mock_category_counts(monkeypatch, {CorrelationPattern.PRIVILEGE_ESCALATION: 2}, {})

    result = await get_threat_analytics(None, uuid.uuid4())

    trend = result.trends[0]
    assert trend.mitre_tactic == "Privilege Escalation"
    assert trend.mitre_technique_ids == ["T1548"]


@pytest.mark.asyncio
async def test_trends_sorted_by_current_count_descending(monkeypatch):
    _mock_category_counts(
        monkeypatch,
        {CorrelationPattern.CREDENTIAL_BRUTE_FORCE: 2, CorrelationPattern.DATA_EXFILTRATION: 9},
        {},
    )

    result = await get_threat_analytics(None, uuid.uuid4())

    assert [t.category for t in result.trends] == [
        CorrelationPattern.DATA_EXFILTRATION,
        CorrelationPattern.CREDENTIAL_BRUTE_FORCE,
    ]


@pytest.mark.asyncio
async def test_window_days_is_echoed_in_the_response(monkeypatch):
    _mock_category_counts(monkeypatch, {}, {})

    result = await get_threat_analytics(None, uuid.uuid4(), window_days=14)

    assert result.window_days == 14


@pytest.mark.asyncio
async def test_no_incidents_produces_an_empty_trend_list(monkeypatch):
    _mock_category_counts(monkeypatch, {}, {})

    result = await get_threat_analytics(None, uuid.uuid4())

    assert result.trends == []


@pytest.mark.asyncio
async def test_queries_two_contiguous_non_overlapping_windows(monkeypatch):
    calls = []

    async def _fake(db, tenant_id, start, end):
        calls.append((start, end))
        return {}

    monkeypatch.setattr("app.services.threat_analytics._category_counts", _fake)

    await get_threat_analytics(None, uuid.uuid4(), window_days=7)

    assert len(calls) == 2
    current_start, current_end = calls[0]
    previous_start, previous_end = calls[1]
    assert previous_end == current_start  # contiguous, not overlapping and not gapped
    assert (current_end - current_start).days == 7
    assert (previous_end - previous_start).days == 7


# ── has_previous_period_data ──────────────────────────────────────

@pytest.mark.asyncio
async def test_has_previous_period_data_is_false_when_the_whole_previous_window_is_empty(monkeypatch):
    """AC: a freshly seeded dataset (all activity in the current window, nothing before it) must be flagged explicitly, not implied via 0%/'new'."""
    _mock_category_counts(monkeypatch, {CorrelationPattern.CREDENTIAL_BRUTE_FORCE: 3}, {})

    result = await get_threat_analytics(None, uuid.uuid4())

    assert result.has_previous_period_data is False


@pytest.mark.asyncio
async def test_has_previous_period_data_is_true_when_any_category_had_previous_activity(monkeypatch):
    _mock_category_counts(monkeypatch, {CorrelationPattern.CREDENTIAL_BRUTE_FORCE: 3}, {CorrelationPattern.LATERAL_MOVEMENT: 1})

    result = await get_threat_analytics(None, uuid.uuid4())

    assert result.has_previous_period_data is True


# ═══════════════════════════════════════════════════════════════════
# Everything below the trend table: KPIs, incident trend, status/
# severity breakdown, MITRE technique tally, affected assets.
# ═══════════════════════════════════════════════════════════════════

def _incident_row(**overrides):
    base = dict(
        id=uuid.uuid4(), status=IncidentStatus.OPEN, category=CorrelationPattern.CREDENTIAL_BRUTE_FORCE,
        alert_ids=["a1"], created_at=datetime(2026, 8, 20, 9, 0, tzinfo=timezone.utc),
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def _alert(**overrides) -> dict:
    base = {
        "alert_id": "a1", "severity": "low", "host_id": "DESKTOP-042", "user": "leo.chen",
        "source": "synthetic", "mitre_technique": None, "mitre_tactic": None,
    }
    base.update(overrides)
    return base


def _mock_full_pipeline(monkeypatch, incidents, alerts, endpoints_by_host=None):
    monkeypatch.setattr("app.services.threat_analytics._current_window_incidents", AsyncMock(return_value=incidents))
    monkeypatch.setattr("app.services.threat_analytics.get_alerts_by_ids", AsyncMock(return_value=alerts))
    monkeypatch.setattr("app.services.threat_analytics._endpoints_by_host", AsyncMock(return_value=endpoints_by_host or {}))


# ── _technique_ids ─────────────────────────────────────────────────

def test_technique_ids_returns_empty_list_for_no_mitre_data():
    assert _technique_ids(_alert(mitre_technique=None)) == []


def test_technique_ids_splits_a_wazuh_style_comma_joined_string():
    assert _technique_ids(_alert(mitre_technique="T1110, T1078")) == ["T1110", "T1078"]


def test_technique_ids_passes_through_a_single_id():
    assert _technique_ids(_alert(mitre_technique="T1068")) == ["T1068"]


# ── _extract_signals ───────────────────────────────────────────────

def test_extract_signals_resolves_severity_from_linked_alerts():
    incident = _incident_row(alert_ids=["a1", "a2"])
    alerts_by_id = {"a1": _alert(alert_id="a1", severity="low"), "a2": _alert(alert_id="a2", severity="critical")}

    signals = _extract_signals(incident, alerts_by_id)

    assert signals.severity == Severity.CRITICAL  # highest of its own alerts, not the last one


def test_extract_signals_severity_is_none_when_no_alert_ids_resolve():
    incident = _incident_row(alert_ids=["missing"])
    signals = _extract_signals(incident, alerts_by_id={})
    assert signals.severity is None


def test_extract_signals_excludes_cloudlens_host_ids_from_hosts():
    """A CloudLens alert's host_id is a cloud resource id, not a real host (matches incident_evidence.py)."""
    incident = _incident_row(alert_ids=["a1"])
    alerts_by_id = {"a1": _alert(alert_id="a1", host_id="arn:aws:iam::123:role/x", source="cloudlens")}

    signals = _extract_signals(incident, alerts_by_id)

    assert signals.hosts == frozenset()


def test_extract_signals_excludes_the_unknown_placeholder_user():
    incident = _incident_row(alert_ids=["a1"])
    alerts_by_id = {"a1": _alert(alert_id="a1", user="unknown")}

    signals = _extract_signals(incident, alerts_by_id)

    assert signals.users == frozenset()


def test_extract_signals_collects_technique_tactic_pairs():
    incident = _incident_row(alert_ids=["a1"])
    alerts_by_id = {"a1": _alert(alert_id="a1", mitre_technique="T1110", mitre_tactic="Credential Access")}

    signals = _extract_signals(incident, alerts_by_id)

    assert signals.technique_tactics == {"T1110": "Credential Access"}


# ── _kpis ──────────────────────────────────────────────────────────

def test_kpis_counts_totals_open_and_critical_high():
    signals = [
        _extract_signals(_incident_row(status=IncidentStatus.OPEN, alert_ids=["a1"]), {"a1": _alert(alert_id="a1", severity="critical")}),
        _extract_signals(_incident_row(status=IncidentStatus.RESOLVED, alert_ids=["a2"]), {"a2": _alert(alert_id="a2", severity="low")}),
    ]

    kpis = _kpis(signals)

    assert kpis.total_incidents == 2
    assert kpis.open_incidents == 1
    assert kpis.critical_high_incidents == 1
    assert kpis.incidents_with_unknown_severity == 0


def test_kpis_counts_an_incident_with_no_resolvable_alerts_as_unknown_severity_not_low():
    signals = [_extract_signals(_incident_row(alert_ids=["missing"]), {})]

    kpis = _kpis(signals)

    assert kpis.incidents_with_unknown_severity == 1
    assert kpis.critical_high_incidents == 0


def test_kpis_counts_distinct_affected_endpoints_and_users_across_incidents():
    signals = [
        _extract_signals(_incident_row(alert_ids=["a1"]), {"a1": _alert(alert_id="a1", host_id="HOST-A", user="leo.chen")}),
        _extract_signals(_incident_row(alert_ids=["a2"]), {"a2": _alert(alert_id="a2", host_id="HOST-A", user="nadia.garcia")}),
    ]

    kpis = _kpis(signals)

    assert kpis.affected_endpoints == 1  # HOST-A only counted once
    assert kpis.affected_users == 2


def test_kpis_counts_distinct_detection_categories():
    signals = [
        _extract_signals(_incident_row(category=CorrelationPattern.CREDENTIAL_BRUTE_FORCE, alert_ids=[]), {}),
        _extract_signals(_incident_row(category=CorrelationPattern.LATERAL_MOVEMENT, alert_ids=[]), {}),
        _extract_signals(_incident_row(category=None, alert_ids=[]), {}),  # manually created, excluded
    ]

    assert _kpis(signals).detection_categories == 2


# ── _status_breakdown / _severity_breakdown ───────────────────────

def test_status_breakdown_includes_every_status_even_with_zero_count():
    signals = [_extract_signals(_incident_row(status=IncidentStatus.OPEN, alert_ids=[]), {})]

    breakdown = {b.status: b.count for b in _status_breakdown(signals)}

    assert breakdown[IncidentStatus.OPEN] == 1
    assert breakdown[IncidentStatus.RESOLVED] == 0
    assert set(breakdown) == set(IncidentStatus)


def test_severity_breakdown_only_counts_incidents_with_known_severity():
    signals = [
        _extract_signals(_incident_row(alert_ids=["a1"]), {"a1": _alert(alert_id="a1", severity="high")}),
        _extract_signals(_incident_row(alert_ids=["missing"]), {}),  # unknown severity, excluded
    ]

    breakdown = {b.severity: b.count for b in _severity_breakdown(signals)}

    assert breakdown[Severity.HIGH] == 1
    assert sum(breakdown.values()) == 1  # the unknown-severity incident isn't silently counted anywhere


# ── _daily_trend ───────────────────────────────────────────────────

def test_daily_trend_zero_fills_every_day_in_the_window():
    start = datetime(2026, 8, 20, 12, 0, tzinfo=timezone.utc)
    end = start + timedelta(days=3)
    signals = [_extract_signals(_incident_row(alert_ids=[], created_at=start + timedelta(days=1, hours=2)), {})]

    trend = _daily_trend(signals, start, end)

    assert [d.date for d in trend] == ["2026-08-20", "2026-08-21", "2026-08-22"]
    assert [d.count for d in trend] == [0, 1, 0]


# ── _mitre_technique_counts ────────────────────────────────────────

def test_mitre_technique_counts_ranks_by_distinct_incident_count():
    incident_a, incident_b = _incident_row(alert_ids=["a1"]), _incident_row(alert_ids=["a2"])
    signals = [
        _extract_signals(incident_a, {"a1": _alert(alert_id="a1", mitre_technique="T1110", mitre_tactic="Credential Access", host_id="HOST-A")}),
        _extract_signals(incident_b, {"a2": _alert(alert_id="a2", mitre_technique="T1110", mitre_tactic="Credential Access", host_id="HOST-B")}),
        _extract_signals(_incident_row(alert_ids=["a3"]), {"a3": _alert(alert_id="a3", mitre_technique="T1068", mitre_tactic="Privilege Escalation")}),
    ]

    counts = _mitre_technique_counts(signals)

    assert counts[0].technique_id == "T1110"
    assert counts[0].incident_count == 2
    assert counts[0].tactic == "Credential Access"
    assert set(counts[0].related_incident_ids) == {str(incident_a.id), str(incident_b.id)}
    assert counts[0].affected_endpoints == ["HOST-A", "HOST-B"]
    assert counts[1].technique_id == "T1068"
    assert counts[1].incident_count == 1


def test_mitre_technique_counts_never_double_counts_repeat_alerts_within_one_incident():
    incident = _incident_row(alert_ids=["a1", "a2"])
    alerts_by_id = {
        "a1": _alert(alert_id="a1", mitre_technique="T1110", mitre_tactic="Credential Access"),
        "a2": _alert(alert_id="a2", mitre_technique="T1110", mitre_tactic="Credential Access"),
    }
    signals = [_extract_signals(incident, alerts_by_id)]

    counts = _mitre_technique_counts(signals)

    assert counts[0].incident_count == 1  # one incident, not one per matching alert


# ── _affected_assets ───────────────────────────────────────────────

def test_affected_assets_ranks_hosts_by_distinct_incident_count_and_carries_dominant_category():
    signals = [
        _extract_signals(_incident_row(category=CorrelationPattern.CREDENTIAL_BRUTE_FORCE, alert_ids=["a1"]), {"a1": _alert(alert_id="a1", host_id="HOST-A")}),
        _extract_signals(_incident_row(category=CorrelationPattern.CREDENTIAL_BRUTE_FORCE, alert_ids=["a2"]), {"a2": _alert(alert_id="a2", host_id="HOST-A")}),
        _extract_signals(_incident_row(category=CorrelationPattern.LATERAL_MOVEMENT, alert_ids=["a3"]), {"a3": _alert(alert_id="a3", host_id="HOST-B")}),
    ]
    endpoints_by_host = {"HOST-A": Endpoint(id=uuid.uuid4(), tenant_id=uuid.uuid4(), host_id="HOST-A", risk_score=90, risk_level=RiskLevel.CRITICAL)}

    assets = _affected_assets(signals, endpoints_by_host)

    assert assets[0].host_id == "HOST-A"
    assert assets[0].incident_count == 2
    assert assets[0].dominant_category == CorrelationPattern.CREDENTIAL_BRUTE_FORCE
    assert assets[0].highest_risk == RiskLevel.CRITICAL
    assert assets[1].host_id == "HOST-B"
    assert assets[1].highest_risk is None  # no Endpoint row for HOST-B -- omitted, not guessed


def test_affected_assets_omits_dominant_category_when_all_its_incidents_are_uncategorized():
    signals = [_extract_signals(_incident_row(category=None, alert_ids=["a1"]), {"a1": _alert(alert_id="a1", host_id="HOST-A")})]

    assets = _affected_assets(signals, {})

    assert assets[0].dominant_category is None


# ── get_threat_analytics (full pipeline, boundary-mocked) ──────────

@pytest.mark.asyncio
async def test_get_threat_analytics_wires_kpis_from_real_alert_derived_signals(monkeypatch):
    _mock_category_counts(monkeypatch, {}, {})
    incident = _incident_row(status=IncidentStatus.OPEN, alert_ids=["a1"])
    _mock_full_pipeline(monkeypatch, incidents=[incident], alerts=[_alert(alert_id="a1", severity="critical", host_id="HOST-A", user="leo.chen")])

    result = await get_threat_analytics(None, uuid.uuid4())

    assert result.kpis.total_incidents == 1
    assert result.kpis.critical_high_incidents == 1
    assert result.kpis.affected_endpoints == 1
    assert result.kpis.affected_users == 1
    assert result.severity_breakdown[0].severity == Severity.CRITICAL
    assert result.severity_breakdown[0].count == 1
    assert result.daily_trend  # non-empty: at least the incident's own day is present


@pytest.mark.asyncio
async def test_get_threat_analytics_handles_a_completely_empty_window(monkeypatch):
    _mock_category_counts(monkeypatch, {}, {})
    _mock_full_pipeline(monkeypatch, incidents=[], alerts=[])

    result = await get_threat_analytics(None, uuid.uuid4(), window_days=7)

    assert result.kpis.total_incidents == 0
    assert result.status_breakdown  # all-status zero rows still present, not an empty list
    assert all(b.count == 0 for b in result.status_breakdown)
    assert result.mitre_techniques == []
    assert result.affected_assets == []
    assert len(result.daily_trend) == 7  # zero-filled window, not empty
