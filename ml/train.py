"""
SafeSOC — Isolation Forest Training Pipeline (SS-049)
Reads the normal-behavior dataset produced by generate_training_data.py
(SS-048), aggregates it into hourly per-host feature vectors, and fits
an Isolation Forest on them, saving the trained bundle to
settings.ANOMALY_MODEL_PATH (ml/model/isolation_forest.pkl).

The 7-feature vector built here (FEATURE_NAMES below) is deliberately
kept in lockstep with app.services.anomaly.FEATURE_NAMES (SS-050) — the
live scoring service extracts the same shape from a host's real-time
sliding window (SS-027) so a trained model can actually be applied to
it. backend/tests/test_anomaly.py asserts the two stay in sync.

How to rerun (from the repo root, with backend/requirements.txt
installed — this script imports app.core.config, so it needs the
backend dependencies on the path, not a separate ml/requirements.txt):

    python ml/generate_training_data.py   # regenerate the dataset (SS-048)
    python ml/train.py                    # fit + save the model

What it expects: a JSON-lines file at DEFAULT_DATASET_PATH (or a path
passed as the first CLI argument), one NormalizedLog-shaped event per
line, each with at least `host_id`, `timestamp`, `log_type`, `action`,
and (for network events) `destination_ip`.
"""

import json
import pickle
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from sklearn.ensemble import IsolationForest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.core.config import settings  # noqa: E402

DEFAULT_DATASET_PATH = Path(__file__).resolve().parent / "data" / "normal_behavior.jsonl"

# Must exactly match app.services.anomaly.FEATURE_NAMES (SS-050) — see
# this module's docstring.
FEATURE_NAMES = (
    "failed_login_count",
    "login_success_count",
    "distinct_destination_ips",
    "process_event_count",
    "hour_of_day",
    "day_of_week",
    "is_after_hours",
)


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _is_after_hours(timestamp: datetime) -> bool:
    """Mirrors app.services.risk_scoring._is_after_hours / app.services.anomaly._is_after_hours."""
    if timestamp.weekday() >= 5:  # Saturday=5, Sunday=6
        return True
    return timestamp.hour < 8 or timestamp.hour >= 18


def load_events(dataset_path: Path = DEFAULT_DATASET_PATH) -> list[dict]:
    with dataset_path.open("r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def build_feature_matrix(events: list[dict]) -> list[list[float]]:
    """
    Aggregate raw events into one feature row per (host_id, hour bucket)
    — the same FEATURE_NAMES shape app.services.anomaly.extract_features()
    computes from a host's live sliding window at serving time.
    """
    buckets: dict[tuple[str, datetime], list[dict]] = defaultdict(list)
    for event in events:
        ts = _parse_timestamp(event["timestamp"])
        bucket_start = ts.replace(minute=0, second=0, microsecond=0)
        buckets[(event["host_id"], bucket_start)].append(event)

    rows = []
    for (_host_id, bucket_start), bucket_events in buckets.items():
        failed_login_count = sum(1 for e in bucket_events if e.get("action") == "failed_login")
        login_success_count = sum(1 for e in bucket_events if e.get("action") == "login_success")
        distinct_destination_ips = len({e["destination_ip"] for e in bucket_events if e.get("destination_ip")})
        process_event_count = sum(1 for e in bucket_events if e.get("log_type") == "process")
        rows.append([
            float(failed_login_count),
            float(login_success_count),
            float(distinct_destination_ips),
            float(process_event_count),
            float(bucket_start.hour),
            float(bucket_start.weekday()),
            1.0 if _is_after_hours(bucket_start) else 0.0,
        ])
    return rows


def train(dataset_path: Path = DEFAULT_DATASET_PATH, output_path: Path | None = None) -> Path:
    """Fit an Isolation Forest on dataset_path's events and save the trained bundle. Returns the path written to."""
    events = load_events(dataset_path)
    if not events:
        raise ValueError(f"No training events found at {dataset_path} — run ml/generate_training_data.py first.")

    X = build_feature_matrix(events)

    model = IsolationForest(n_estimators=200, random_state=42)
    model.fit(X)

    # score_samples: lower = more abnormal. Flip sign so higher = more
    # abnormal, then record the training distribution's min/max so the
    # scoring service (SS-050) can normalize a live raw score into a
    # calibrated 0-1 range rather than an unbounded one.
    raw_scores = [-s for s in model.score_samples(X)]

    bundle = {
        "model": model,
        "feature_names": FEATURE_NAMES,
        "score_min": min(raw_scores),
        "score_max": max(raw_scores),
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "training_samples": len(X),
    }

    output_path = output_path or Path(settings.ANOMALY_MODEL_PATH)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("wb") as f:
        pickle.dump(bundle, f)

    return output_path


def main():
    dataset_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_DATASET_PATH
    output_path = train(dataset_path)
    print(f"Trained Isolation Forest on {dataset_path} -> {output_path}")


if __name__ == "__main__":
    main()
