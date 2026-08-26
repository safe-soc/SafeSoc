"""
SafeSOC — Threat Analytics Rollup Service Tests (SS-111)
Real tenant/date-range SQL filtering (_category_counts' WHERE clause)
can't be meaningfully proven against a fake session that just hands
back a canned row list — same limitation acknowledged throughout this
test suite (see tests/test_incidents.py's own notes) — so that part is
verified live against Docker Postgres instead. These tests cover the
row-mapping shape and the full trend-computation logic (percentage
math, MITRE mapping, sorting) by mocking _category_counts directly.
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from app.core.enums import CorrelationPattern
from app.services.threat_analytics import _category_counts, get_threat_analytics


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
    assert trend.mitre_technique_ids == ["T1068"]


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
