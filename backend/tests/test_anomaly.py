"""
SafeSOC — Anomaly Detection Service Tests (SS-050)
"""

import random
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sklearn.ensemble import IsolationForest

from app.core.config import settings
from app.services import anomaly

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture(autouse=True)
def _reset_model_cache():
    """anomaly._load_model() caches process-wide — don't let one test's monkeypatched model leak into the next."""
    anomaly._model_cache = None
    yield
    anomaly._model_cache = None


# ── SS-050: feature extraction ──────────────────────────────────

def test_is_after_hours_matches_business_hours_definition():
    business_hours = datetime(2026, 6, 3, 14, 0, tzinfo=timezone.utc)  # Wednesday 2pm
    overnight = datetime(2026, 6, 3, 23, 0, tzinfo=timezone.utc)  # Wednesday 11pm
    weekend = datetime(2026, 6, 6, 14, 0, tzinfo=timezone.utc)  # Saturday 2pm

    assert anomaly._is_after_hours(business_hours) is False
    assert anomaly._is_after_hours(overnight) is True
    assert anomaly._is_after_hours(weekend) is True


def test_extract_features_counts_events_by_type():
    events = [
        {"action": "failed_login"},
        {"action": "failed_login"},
        {"action": "login_success"},
        {"log_type": "process", "action": "process_start"},
        {"log_type": "network", "action": "outbound_connection", "destination_ip": "10.0.0.1"},
        {"log_type": "network", "action": "outbound_connection", "destination_ip": "10.0.0.1"},  # dup
        {"log_type": "network", "action": "outbound_connection", "destination_ip": "10.0.0.2"},
    ]
    timestamp = datetime(2026, 6, 3, 14, 0, tzinfo=timezone.utc)  # Wednesday 2pm

    features = anomaly.extract_features(events, timestamp)

    assert dict(zip(anomaly.FEATURE_NAMES, features)) == {
        "failed_login_count": 2.0,
        "login_success_count": 1.0,
        "distinct_destination_ips": 2.0,
        "process_event_count": 1.0,
        "hour_of_day": 14.0,
        "day_of_week": 2.0,
        "is_after_hours": 0.0,
    }


def test_extract_features_on_an_empty_window_is_all_zero_except_temporal():
    timestamp = datetime(2026, 6, 6, 3, 0, tzinfo=timezone.utc)  # Saturday 3am

    features = anomaly.extract_features([], timestamp)

    row = dict(zip(anomaly.FEATURE_NAMES, features))
    assert row["failed_login_count"] == 0.0
    assert row["distinct_destination_ips"] == 0.0
    assert row["hour_of_day"] == 3.0
    assert row["day_of_week"] == 5.0
    assert row["is_after_hours"] == 1.0


def test_extract_features_ignores_events_without_a_destination_ip():
    events = [{"log_type": "network", "action": "outbound_connection"}]  # no destination_ip
    timestamp = datetime(2026, 6, 3, 14, 0, tzinfo=timezone.utc)

    features = anomaly.extract_features(events, timestamp)

    assert dict(zip(anomaly.FEATURE_NAMES, features))["distinct_destination_ips"] == 0.0


# ── SS-050: model loading + scoring ─────────────────────────────

def test_score_features_returns_none_when_no_model_is_trained_yet(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "ANOMALY_MODEL_PATH", str(tmp_path / "does-not-exist.pkl"))

    result = anomaly.score_features([0.0] * len(anomaly.FEATURE_NAMES))

    assert result is None


def _fit_test_bundle() -> dict:
    """
    A small, real IsolationForest fit on synthetic 'normal' feature
    rows (light activity, business hours) — mirrors what ml/train.py
    produces, so score_features() is exercised against a real model,
    not a mock.
    """
    random.seed(42)
    normal_rows = []
    for _ in range(200):
        hour = random.choice(range(8, 18))  # business hours
        normal_rows.append([
            float(random.randint(0, 1)),   # failed_login_count
            float(random.randint(1, 3)),   # login_success_count
            float(random.randint(0, 2)),   # distinct_destination_ips
            float(random.randint(0, 3)),   # process_event_count
            float(hour),
            float(random.choice(range(0, 5))),  # weekday
            0.0,  # is_after_hours
        ])

    model = IsolationForest(n_estimators=100, random_state=42)
    model.fit(normal_rows)
    raw_scores = [-s for s in model.score_samples(normal_rows)]

    return {"model": model, "score_min": min(raw_scores), "score_max": max(raw_scores)}


def test_score_features_flags_a_known_anomalous_vector_above_threshold(monkeypatch):
    monkeypatch.setattr(anomaly, "_load_model", lambda: _fit_test_bundle())

    # Brute force at 3am on a Saturday — nothing like the training distribution.
    anomalous = [50.0, 0.0, 20.0, 30.0, 3.0, 5.0, 1.0]
    result = anomaly.score_features(anomalous)

    assert result is not None
    assert result.score >= settings.ANOMALY_THRESHOLD
    assert result.is_anomalous is True


def test_score_features_does_not_flag_a_known_normal_vector(monkeypatch):
    monkeypatch.setattr(anomaly, "_load_model", lambda: _fit_test_bundle())

    # Squarely inside the training distribution: light weekday business-hours activity.
    normal = [0.0, 2.0, 1.0, 1.0, 14.0, 2.0, 0.0]
    result = anomaly.score_features(normal)

    assert result is not None
    assert result.score < settings.ANOMALY_THRESHOLD
    assert result.is_anomalous is False


def test_score_features_clips_to_the_0_1_range_beyond_the_training_extremes(monkeypatch):
    monkeypatch.setattr(anomaly, "_load_model", lambda: _fit_test_bundle())

    extreme = [1000.0, 0.0, 500.0, 800.0, 3.0, 6.0, 1.0]
    result = anomaly.score_features(extreme)

    assert result is not None
    assert 0.0 <= result.score <= 1.0


def test_load_model_caches_across_calls(monkeypatch, tmp_path):
    import pickle

    model_path = tmp_path / "isolation_forest.pkl"
    with model_path.open("wb") as f:
        pickle.dump({"model": "sentinel", "score_min": 0.0, "score_max": 1.0}, f)
    monkeypatch.setattr(settings, "ANOMALY_MODEL_PATH", str(model_path))

    first = anomaly._load_model()
    model_path.unlink()  # prove the second call doesn't re-read the file
    second = anomaly._load_model()

    assert first is second


# ── SS-050: end-to-end score_alert() ────────────────────────────

@pytest.mark.asyncio
async def test_score_alert_pulls_the_hosts_window_and_scores_it(monkeypatch):
    captured = {}

    async def fake_get_events(tenant_id, host_id, window_minutes, *, now=None):
        captured["args"] = (tenant_id, host_id, window_minutes, now)
        return [{"action": "failed_login"}]

    monkeypatch.setattr(anomaly, "get_events", fake_get_events)
    monkeypatch.setattr(anomaly, "_load_model", lambda: _fit_test_bundle())

    timestamp = datetime(2026, 6, 3, 14, 0, tzinfo=timezone.utc)
    result = await anomaly.score_alert("acme-corp", "DESKTOP-042", timestamp)

    assert result is not None
    assert captured["args"][0] == "acme-corp"
    assert captured["args"][1] == "DESKTOP-042"
    assert captured["args"][2] == 60
    assert captured["args"][3] == timestamp.timestamp()


@pytest.mark.asyncio
async def test_score_alert_returns_none_when_no_model_is_trained_yet(monkeypatch):
    async def fake_get_events(*args, **kwargs):
        return []

    monkeypatch.setattr(anomaly, "get_events", fake_get_events)
    monkeypatch.setattr(anomaly, "_load_model", lambda: None)

    result = await anomaly.score_alert("acme-corp", "DESKTOP-042", datetime.now(timezone.utc))

    assert result is None


# ── SS-050: train/serve feature-schema parity ───────────────────

def test_feature_names_match_the_training_pipelines_schema():
    """
    ml/train.py aggregates SS-048's dataset into features independently
    of this module (see anomaly.py's own docstring for why) — this is
    the safety net ensuring the two never silently drift apart.
    """
    from ml.train import FEATURE_NAMES as TRAIN_FEATURE_NAMES

    assert anomaly.FEATURE_NAMES == TRAIN_FEATURE_NAMES
