"""
SafeSOC — Isolation Forest Training Pipeline Tests (SS-049)
Reaches ml/train.py the same way it reaches backend/app/core/config.py
at runtime: via a sys.path insert, mirroring the real script's own
import strategy (see its module docstring).
"""

import json
import pickle
import sys
from pathlib import Path

import pytest
from sklearn.ensemble import IsolationForest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ml.train import FEATURE_NAMES, _is_after_hours, build_feature_matrix, load_events, train  # noqa: E402


def _event(**overrides) -> dict:
    base = {
        "host_id": "DESKTOP-001",
        "timestamp": "2026-06-03T14:30:00+00:00",  # Wednesday, 14:30
        "log_type": "authentication",
        "action": "failed_login",
    }
    base.update(overrides)
    return base


def test_is_after_hours_matches_risk_scorings_definition():
    from datetime import datetime, timezone

    business_hours = datetime(2026, 6, 3, 14, 0, tzinfo=timezone.utc)  # Wednesday 2pm
    overnight = datetime(2026, 6, 3, 23, 0, tzinfo=timezone.utc)  # Wednesday 11pm
    weekend = datetime(2026, 6, 6, 14, 0, tzinfo=timezone.utc)  # Saturday 2pm

    assert _is_after_hours(business_hours) is False
    assert _is_after_hours(overnight) is True
    assert _is_after_hours(weekend) is True


def test_build_feature_matrix_buckets_by_host_and_hour():
    events = [
        _event(action="failed_login"),
        _event(action="failed_login"),
        _event(action="login_success"),
        _event(log_type="process", action="process_start"),
        _event(log_type="network", action="outbound_connection", destination_ip="10.0.0.1"),
        _event(log_type="network", action="outbound_connection", destination_ip="10.0.0.2"),
        _event(log_type="network", action="outbound_connection", destination_ip="10.0.0.1"),  # duplicate dest
    ]

    matrix = build_feature_matrix(events)

    assert len(matrix) == 1  # all events fall in the same host+hour bucket
    row = dict(zip(FEATURE_NAMES, matrix[0]))
    assert row["failed_login_count"] == 2.0
    assert row["login_success_count"] == 1.0
    assert row["process_event_count"] == 1.0
    assert row["distinct_destination_ips"] == 2.0  # 10.0.0.1 counted once
    assert row["hour_of_day"] == 14.0
    assert row["day_of_week"] == 2.0  # Wednesday
    assert row["is_after_hours"] == 0.0


def test_build_feature_matrix_separates_different_hosts_and_hours():
    events = [
        _event(host_id="DESKTOP-001", timestamp="2026-06-03T14:30:00+00:00"),
        _event(host_id="DESKTOP-002", timestamp="2026-06-03T14:45:00+00:00"),
        _event(host_id="DESKTOP-001", timestamp="2026-06-03T15:05:00+00:00"),
    ]

    matrix = build_feature_matrix(events)

    assert len(matrix) == 3  # (001, 14h), (002, 14h), (001, 15h) are all distinct buckets


def test_load_events_reads_jsonl(tmp_path):
    dataset_path = tmp_path / "events.jsonl"
    events = [_event(), _event(action="login_success")]
    dataset_path.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")

    loaded = load_events(dataset_path)

    assert loaded == events


def test_train_raises_a_clear_error_on_an_empty_dataset(tmp_path):
    empty_dataset = tmp_path / "empty.jsonl"
    empty_dataset.write_text("", encoding="utf-8")

    with pytest.raises(ValueError, match="No training events found"):
        train(empty_dataset, output_path=tmp_path / "model.pkl")


def test_train_saves_a_bundle_at_the_given_output_path(tmp_path):
    from ml.generate_training_data import generate_dataset, write_dataset

    dataset_path = tmp_path / "normal_behavior.jsonl"
    write_dataset(generate_dataset(days=3, hosts=["DESKTOP-001", "DESKTOP-002"]), dataset_path)
    output_path = tmp_path / "model" / "isolation_forest.pkl"

    returned_path = train(dataset_path, output_path=output_path)

    assert returned_path == output_path
    assert output_path.exists()

    with output_path.open("rb") as f:
        bundle = pickle.load(f)

    assert isinstance(bundle["model"], IsolationForest)
    assert bundle["feature_names"] == FEATURE_NAMES
    assert bundle["score_min"] <= bundle["score_max"]
    assert bundle["training_samples"] > 0
    assert bundle["trained_at"]  # a real, non-empty ISO timestamp string
