"""
SafeSOC — Anomaly Detection Service
Two complementary techniques from SRS §3.3:

 - Isolation Forest scoring (SS-050): loads the model trained by
   ml/train.py (SS-049) and scores a host's recent behavior around a
   new alert 0-1, flagging anomalies above ANOMALY_THRESHOLD.
 - Z-score network volume spike detection (SS-051): a lightweight
   statistical complement needing no trained model — flags a sudden
   burst in a host's outbound-connection rate against
   NETWORK_ANOMALY_ZSCORE_THRESHOLD.

Both reuse the correlation engine's per-host sliding window (SS-027)
rather than standing up separate storage — the same window the
attack-chain detectors (SS-028) already read from. Window events are
stored by app.workers.correlation_worker in a fixed, minimal shape:
{alert_id, log_type, action, severity, destination_ip} — no per-event
timestamp — so "temporal features" below describe the alert being
scored, not each individual windowed event, and the Z-score detector
compares *counts across two time-bounded window queries* rather than
per-event timestamps.

FEATURE_NAMES is deliberately kept in lockstep with ml/train.py's
identically-named tuple: that script aggregates SS-048's static
training corpus into this same shape so a model trained on it can
actually be applied here. tests/test_anomaly.py asserts the two stay
in sync.
"""

import math
import pickle
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Sequence

from app.core.config import settings
from app.services.correlation import get_events

FEATURE_NAMES = (
    "failed_login_count",
    "login_success_count",
    "distinct_destination_ips",
    "process_event_count",
    "hour_of_day",
    "day_of_week",
    "is_after_hours",
)


def _is_after_hours(timestamp: datetime) -> bool:
    """Mirrors app.services.risk_scoring._is_after_hours — same after-hours definition, applied here to the scored alert's own timestamp."""
    if timestamp.weekday() >= 5:  # Saturday=5, Sunday=6
        return True
    return timestamp.hour < 8 or timestamp.hour >= 18


def extract_features(events: Sequence[dict[str, Any]], timestamp: datetime) -> list[float]:
    """
    Build the FEATURE_NAMES vector for an alert at `timestamp`, from its
    host's recent sliding-window events (SS-027) leading up to it. Pure
    and deterministic — testable without a trained model on disk (AC).
    """
    failed_login_count = sum(1 for e in events if e.get("action") == "failed_login")
    login_success_count = sum(1 for e in events if e.get("action") == "login_success")
    distinct_destination_ips = len({e["destination_ip"] for e in events if e.get("destination_ip")})
    process_event_count = sum(1 for e in events if e.get("log_type") == "process")

    return [
        float(failed_login_count),
        float(login_success_count),
        float(distinct_destination_ips),
        float(process_event_count),
        float(timestamp.hour),
        float(timestamp.weekday()),
        1.0 if _is_after_hours(timestamp) else 0.0,
    ]


@dataclass(frozen=True)
class AnomalyResult:
    score: float  # 0.0-1.0, higher = more anomalous
    is_anomalous: bool


_model_cache: Optional[dict] = None


def _load_model() -> Optional[dict]:
    """
    Load (and cache in-process) the trained bundle saved by ml/train.py:
    {"model": IsolationForest, "score_min": float, "score_max": float, ...}.
    Returns None if no model has been trained yet, rather than raising
    — scoring degrades to "unknown" instead of crashing a deployment
    that hasn't run SS-049's training step.
    """
    global _model_cache
    if _model_cache is not None:
        return _model_cache

    path = Path(settings.ANOMALY_MODEL_PATH)
    if not path.exists():
        return None

    with path.open("rb") as f:
        _model_cache = pickle.load(f)
    return _model_cache


def score_features(features: Sequence[float]) -> Optional[AnomalyResult]:
    """
    Score a feature vector (as produced by extract_features) against
    the trained model. None if no model is available yet.

    The model's raw score_samples() output is unbounded (lower = more
    abnormal); it's flipped and normalized against the training
    distribution's min/max (saved alongside the model by ml/train.py)
    into a calibrated 0.0-1.0 range, clipped at the edges so a live
    score more extreme than anything seen in training still saturates
    at 0 or 1 rather than escaping the documented range.
    """
    bundle = _load_model()
    if bundle is None:
        return None

    model = bundle["model"]
    score_min = bundle["score_min"]
    score_max = bundle["score_max"]

    raw_score = -model.score_samples([list(features)])[0]
    span = score_max - score_min
    normalized = (raw_score - score_min) / span if span > 0 else 0.0
    # score_samples() returns numpy scalars — cast to native Python types
    # so callers (and JSON serialization) get a plain float/bool, not
    # numpy.float64/numpy.bool_.
    score = float(max(0.0, min(1.0, normalized)))

    return AnomalyResult(score=score, is_anomalous=bool(score >= settings.ANOMALY_THRESHOLD))


async def score_alert(
    tenant_id: str, host_id: str, timestamp: datetime, *, window_minutes: int = 60
) -> Optional[AnomalyResult]:
    """
    Score a new alert's behavioral context: pulls host_id's recent
    sliding-window events (SS-027) and scores the resulting feature
    vector against the trained model (SS-050). None if no model has
    been trained yet.
    """
    events = await get_events(tenant_id, host_id, window_minutes, now=timestamp.timestamp())
    features = extract_features(events, timestamp)
    return score_features(features)


# ── SS-051: Z-score network volume spike detection ──────────────
#
# No trained model or per-event timestamps needed: two get_events()
# calls with different (window_minutes, now) pull a "recent" window and
# a preceding, non-overlapping "baseline" window from the same sliding
# window SS-050 reads from. The baseline's rate is scaled to the
# recent window's duration to get an expected count, and a Poisson
# approximation (variance == mean, so stddev == sqrt(expected)) gives a
# z-score without needing a stored history of past bucket counts.

RECENT_WINDOW_MINUTES = 5
BASELINE_WINDOW_MINUTES = 60


@dataclass(frozen=True)
class VolumeSpike:
    z_score: float
    observed_count: int
    expected_count: float


def _poisson_zscore(observed: int, expected: float) -> float:
    if expected <= 0:
        return float("inf") if observed > 0 else 0.0
    return (observed - expected) / math.sqrt(expected)


def detect_network_volume_spike(
    baseline_events: Sequence[dict[str, Any]],
    recent_events: Sequence[dict[str, Any]],
    *,
    recent_window_minutes: int = RECENT_WINDOW_MINUTES,
    baseline_window_minutes: int = BASELINE_WINDOW_MINUTES,
) -> Optional[VolumeSpike]:
    """
    Flag a sudden spike in outbound network-event volume: compares
    recent_events' network-event count against the rate implied by
    baseline_events (a longer, earlier, non-overlapping window), and
    flags if the deviation exceeds NETWORK_ANOMALY_ZSCORE_THRESHOLD
    standard deviations under a Poisson approximation. None if the
    recent count isn't a statistically surprising deviation — i.e.
    steady-state traffic (AC).
    """
    baseline_count = sum(1 for e in baseline_events if e.get("log_type") == "network")
    recent_count = sum(1 for e in recent_events if e.get("log_type") == "network")

    expected_count = baseline_count * (recent_window_minutes / baseline_window_minutes)
    z_score = _poisson_zscore(recent_count, expected_count)

    if abs(z_score) < settings.NETWORK_ANOMALY_ZSCORE_THRESHOLD:
        return None
    return VolumeSpike(z_score=z_score, observed_count=recent_count, expected_count=expected_count)


async def check_network_volume_spike(
    tenant_id: str,
    host_id: str,
    *,
    now: Optional[float] = None,
    recent_window_minutes: int = RECENT_WINDOW_MINUTES,
    baseline_window_minutes: int = BASELINE_WINDOW_MINUTES,
) -> Optional[VolumeSpike]:
    """
    Pull host_id's sliding window (SS-027) as two non-overlapping
    periods — the last `recent_window_minutes` and the
    `baseline_window_minutes` immediately before that — and check for a
    volume spike (SS-051) between them.
    """
    now = now if now is not None else time.time()
    recent_events = await get_events(tenant_id, host_id, recent_window_minutes, now=now)
    baseline_events = await get_events(
        tenant_id, host_id, baseline_window_minutes, now=now - (recent_window_minutes * 60)
    )
    return detect_network_volume_spike(
        baseline_events,
        recent_events,
        recent_window_minutes=recent_window_minutes,
        baseline_window_minutes=baseline_window_minutes,
    )
