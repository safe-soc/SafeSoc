"""
SafeSOC — Risk Scoring Service Tests
"""

import uuid
from datetime import datetime, timezone

import pytest

from app.core.config import settings
from app.core.enums import RiskLevel
from app.models.endpoint import Endpoint
from app.services.risk_scoring import calculate_risk_score, list_endpoints, recalculate_endpoint_score

# Wednesday, business hours (08:00-18:00 UTC) -> not after-hours.
_BUSINESS_HOURS = "2026-08-05T12:00:00+00:00"
# Saturday -> after-hours (weekend).
_WEEKEND = "2026-08-08T12:00:00+00:00"
# Wednesday, 02:00 UTC -> after-hours (outside 08:00-18:00).
_NIGHT = "2026-08-05T02:00:00+00:00"


def _alert(severity="low", timestamp=_BUSINESS_HOURS, mitre_technique=None, ti_result=None, anomaly_score=None):
    return {
        "severity": severity,
        "timestamp": timestamp,
        "mitre_technique": mitre_technique,
        "ti_result": ti_result,
        "anomaly_score": anomaly_score,
    }


def _now_at(timestamp: str) -> datetime:
    return datetime.fromisoformat(timestamp)


# ── Empty input ─────────────────────────────────────────────────

def test_no_alerts_scores_zero_and_low():
    result = calculate_risk_score([])

    assert result.score == 0
    assert result.level == RiskLevel.LOW


# ── Severity weighting (AC: matches the documented formula) ──────

def test_single_critical_alert_scores_the_critical_weight():
    result = calculate_risk_score([_alert(severity="critical")], now=_now_at(_BUSINESS_HOURS))

    assert result.score == settings.RISK_SCORE_CRITICAL


def test_severity_points_sum_across_multiple_alerts():
    alerts = [_alert(severity="high"), _alert(severity="medium")]

    result = calculate_risk_score(alerts, now=_now_at(_BUSINESS_HOURS))

    assert result.score == settings.RISK_SCORE_HIGH + settings.RISK_SCORE_MEDIUM


# ── Bonuses ────────────────────────────────────────────────────

def test_ti_malicious_bonus_is_added():
    alert = _alert(severity="low", ti_result={"is_malicious": True})

    result = calculate_risk_score([alert], now=_now_at(_BUSINESS_HOURS))

    assert result.score == settings.RISK_SCORE_LOW + settings.RISK_SCORE_TI_MALICIOUS_BONUS


def test_ti_non_malicious_result_does_not_add_a_bonus():
    alert = _alert(severity="low", ti_result={"is_malicious": False})

    result = calculate_risk_score([alert], now=_now_at(_BUSINESS_HOURS))

    assert result.score == settings.RISK_SCORE_LOW


def test_anomaly_bonus_added_when_at_or_above_threshold():
    alert = _alert(severity="low", anomaly_score=settings.ANOMALY_THRESHOLD)

    result = calculate_risk_score([alert], now=_now_at(_BUSINESS_HOURS))

    assert result.score == settings.RISK_SCORE_LOW + settings.RISK_SCORE_ANOMALY_BONUS


def test_anomaly_bonus_not_added_when_below_threshold():
    alert = _alert(severity="low", anomaly_score=settings.ANOMALY_THRESHOLD - 0.1)

    result = calculate_risk_score([alert], now=_now_at(_BUSINESS_HOURS))

    assert result.score == settings.RISK_SCORE_LOW


def test_mitre_bonus_added_when_technique_present():
    alert = _alert(severity="low", mitre_technique="T1110")

    result = calculate_risk_score([alert], now=_now_at(_BUSINESS_HOURS))

    assert result.score == settings.RISK_SCORE_LOW + settings.RISK_SCORE_MITRE_BONUS


def test_after_hours_bonus_added_on_a_weekend():
    alert = _alert(severity="low", timestamp=_WEEKEND)

    result = calculate_risk_score([alert], now=_now_at(_WEEKEND))

    assert result.score == settings.RISK_SCORE_LOW + settings.RISK_SCORE_AFTER_HOURS_BONUS


def test_after_hours_bonus_added_at_night_on_a_weekday():
    alert = _alert(severity="low", timestamp=_NIGHT)

    result = calculate_risk_score([alert], now=_now_at(_NIGHT))

    assert result.score == settings.RISK_SCORE_LOW + settings.RISK_SCORE_AFTER_HOURS_BONUS


def test_business_hours_alert_gets_no_after_hours_bonus():
    alert = _alert(severity="low", timestamp=_BUSINESS_HOURS)

    result = calculate_risk_score([alert], now=_now_at(_BUSINESS_HOURS))

    assert result.score == settings.RISK_SCORE_LOW


# ── Time decay (AC: reduces score for hosts with no recent activity) ──

def test_time_decay_reduces_score_as_hours_since_the_last_alert_increase():
    alert = _alert(severity="high")  # 20 points, business hours, no other bonuses
    at_alert_time = _now_at(_BUSINESS_HOURS)
    ten_hours_later = datetime.fromisoformat("2026-08-05T22:00:00+00:00")

    fresh = calculate_risk_score([alert], now=at_alert_time)
    decayed = calculate_risk_score([alert], now=ten_hours_later)

    assert fresh.score == settings.RISK_SCORE_HIGH
    # decay_factor = 1 - 0.04*10 = 0.6 -> 20*0.6 = 12
    assert decayed.score == round(settings.RISK_SCORE_HIGH * (1 - settings.RISK_TIME_DECAY_PER_HOUR * 10))
    assert decayed.score < fresh.score


def test_time_decay_floors_at_zero_for_a_long_idle_host():
    alert = _alert(severity="critical")
    long_idle = datetime.fromisoformat("2026-09-05T12:00:00+00:00")  # 31 days later

    result = calculate_risk_score([alert], now=long_idle)

    assert result.score == 0
    assert result.level == RiskLevel.LOW


def test_decay_is_based_on_the_most_recent_alert_not_the_oldest():
    """A host with one old and one fresh alert should decay based on the fresh one."""
    old_alert = _alert(severity="critical", timestamp="2026-01-01T12:00:00+00:00")
    fresh_alert = _alert(severity="low", timestamp=_BUSINESS_HOURS)

    result = calculate_risk_score([old_alert, fresh_alert], now=_now_at(_BUSINESS_HOURS))

    # No decay at all, since the most recent alert is exactly "now".
    assert result.score == settings.RISK_SCORE_CRITICAL + settings.RISK_SCORE_LOW


# ── Cap at 100 ─────────────────────────────────────────────────

def test_score_is_capped_at_100():
    alert = _alert(
        severity="critical",
        mitre_technique="T1110",
        ti_result={"is_malicious": True},
        anomaly_score=0.99,
    )

    result = calculate_risk_score([alert], now=_now_at(_BUSINESS_HOURS))

    assert result.score == 100
    assert result.level == RiskLevel.CRITICAL


# ── Risk level mapping (AC: four risk levels per SRS §3.3) ────────

def _n_low_alerts(n: int) -> list[dict]:
    return [_alert(severity="low") for _ in range(n)]


@pytest.mark.parametrize(
    "alert_count,expected_level",
    [
        (1, RiskLevel.LOW),       # 5 points
        (4, RiskLevel.LOW),       # 20 points
        (5, RiskLevel.MEDIUM),    # 25 points - lower boundary of Medium
        (9, RiskLevel.MEDIUM),    # 45 points
        (10, RiskLevel.HIGH),     # 50 points - lower boundary of High
        (14, RiskLevel.HIGH),     # 70 points
        (15, RiskLevel.CRITICAL),  # 75 points - lower boundary of Critical
        (20, RiskLevel.CRITICAL),  # 100 points (capped)
    ],
)
def test_score_maps_to_the_correct_risk_level(alert_count, expected_level):
    result = calculate_risk_score(_n_low_alerts(alert_count), now=_now_at(_BUSINESS_HOURS))

    assert result.level == expected_level


# ── Config-driven, not hardcoded ──────────────────────────────────

def test_severity_weight_is_read_from_config_not_hardcoded(monkeypatch):
    monkeypatch.setattr(settings, "RISK_SCORE_LOW", 99)

    result = calculate_risk_score([_alert(severity="low")], now=_now_at(_BUSINESS_HOURS))

    assert result.score == 99


# ── SS-033: recalculate_endpoint_score (persistence) ────────────────


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)


class _FakeSession:
    def __init__(self, existing_endpoints=None):
        self.existing_endpoints: list[Endpoint] = list(existing_endpoints or [])
        self.added: list = []
        self.commit_count = 0

    async def execute(self, stmt):
        return _FakeResult(self.existing_endpoints)

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        self.commit_count += 1
        for obj in self.added:
            if obj not in self.existing_endpoints:
                self.existing_endpoints.append(obj)
        self.added = []

    async def refresh(self, obj):
        pass


def _alert_now(severity="critical") -> dict:
    """An alert timestamped at the real current moment, so calculate_risk_score's
    default now=datetime.now(timezone.utc) applies zero decay regardless of
    when the test suite happens to run (unlike _alert()'s fixed _BUSINESS_HOURS)."""
    return _alert(severity=severity, timestamp=datetime.now(timezone.utc).isoformat())


@pytest.mark.asyncio
async def test_recalculate_endpoint_score_creates_a_new_endpoint_when_none_exists():
    session = _FakeSession()
    tenant_id = uuid.uuid4()

    endpoint = await recalculate_endpoint_score(session, tenant_id, "DESKTOP-042", [_alert_now()])

    assert endpoint.tenant_id == tenant_id
    assert endpoint.host_id == "DESKTOP-042"
    # >= rather than an exact number: a real "now" may or may not land in the
    # after-hours bonus window depending on when the suite happens to run.
    assert endpoint.risk_score >= settings.RISK_SCORE_CRITICAL
    assert session.commit_count == 1


@pytest.mark.asyncio
async def test_recalculate_endpoint_score_updates_an_existing_endpoint_in_place():
    tenant_id = uuid.uuid4()
    existing = Endpoint(id=uuid.uuid4(), tenant_id=tenant_id, host_id="DESKTOP-042", risk_score=5, risk_level=RiskLevel.LOW)
    session = _FakeSession(existing_endpoints=[existing])

    endpoint = await recalculate_endpoint_score(session, tenant_id, "DESKTOP-042", [_alert_now()])

    assert endpoint.id == existing.id
    assert endpoint.risk_score != 5  # updated from the stale value
    assert endpoint.risk_score >= settings.RISK_SCORE_CRITICAL
    assert len(session.existing_endpoints) == 1  # updated in place, not duplicated


@pytest.mark.asyncio
async def test_recalculate_endpoint_score_reflects_zero_alerts_as_zero_risk():
    tenant_id = uuid.uuid4()
    existing = Endpoint(id=uuid.uuid4(), tenant_id=tenant_id, host_id="DESKTOP-042", risk_score=80, risk_level=RiskLevel.CRITICAL)
    session = _FakeSession(existing_endpoints=[existing])

    endpoint = await recalculate_endpoint_score(session, tenant_id, "DESKTOP-042", [])

    assert endpoint.risk_score == 0
    assert endpoint.risk_level == RiskLevel.LOW


# ── SS-034: list_endpoints ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_endpoints_returns_the_tenants_known_endpoints():
    tenant_id = uuid.uuid4()
    existing = [
        Endpoint(id=uuid.uuid4(), tenant_id=tenant_id, host_id="DESKTOP-042", risk_score=20, risk_level=RiskLevel.LOW),
        Endpoint(id=uuid.uuid4(), tenant_id=tenant_id, host_id="WEB-SERVER-01", risk_score=80, risk_level=RiskLevel.CRITICAL),
    ]
    session = _FakeSession(existing_endpoints=existing)

    endpoints = await list_endpoints(session, tenant_id)

    assert len(endpoints) == 2
    assert {e.host_id for e in endpoints} == {"DESKTOP-042", "WEB-SERVER-01"}


@pytest.mark.asyncio
async def test_list_endpoints_returns_empty_list_when_none_exist():
    session = _FakeSession()

    assert await list_endpoints(session, uuid.uuid4()) == []


# Note: sorting by risk_score descending happens in the SQL ORDER BY
# clause itself - a fake session that hands back a canned list can't
# meaningfully prove real ordering, same caveat as elsewhere in this
# codebase (e.g. tests/test_incidents.py). Verified against live
# Postgres in Docker instead.
