"""
SafeSOC — Training Data Generator Tests (SS-048)
ml/ isn't a Python package under backend/, so these tests reach it the
same way ml/train.py (SS-049) reaches back into backend/app: by adding
the repo root to sys.path. Exercises the real generator, not a mock.
"""

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ml.generate_training_data import _expected_events, _sample_count, generate_dataset, write_dataset  # noqa: E402

from app.schemas.log import NormalizedLog  # noqa: E402


def test_business_hours_are_expected_to_be_busier_than_overnight():
    """Diurnal pattern (AC): a weekday mid-afternoon hour must be busier than a weekday overnight hour."""
    business_hour = _expected_events(hour=14, weekday=2)  # Wednesday 2pm
    overnight_hour = _expected_events(hour=3, weekday=2)  # Wednesday 3am

    assert business_hour > overnight_hour


def test_weekdays_are_expected_to_be_busier_than_weekends():
    """Weekly pattern (AC): the same hour is busier on a weekday than on a weekend."""
    weekday = _expected_events(hour=14, weekday=2)  # Wednesday
    weekend = _expected_events(hour=14, weekday=5)  # Saturday

    assert weekday > weekend


def test_expected_events_is_never_negative():
    for hour in range(24):
        for weekday in range(7):
            assert _expected_events(hour, weekday) >= 0


def test_sample_count_of_zero_expectation_is_always_zero():
    assert _sample_count(0.0) == 0


def test_sample_count_is_never_negative():
    # A low expectation still shouldn't ever sample below zero, even
    # though gauss() can draw negative values before clipping.
    assert all(_sample_count(0.1) >= 0 for _ in range(200))


def test_generated_dataset_is_not_uniformly_random_across_the_day():
    """
    The generated EVENT VOLUME (not just the expectation curve) must
    reflect the diurnal pattern — guards against the curve existing but
    never actually being applied when building the dataset.
    """
    events = generate_dataset(days=7, hosts=["DESKTOP-001", "DESKTOP-002"])

    business_hour_count = sum(
        1 for e in events if datetime.fromisoformat(e["timestamp"]).hour == 14
    )
    overnight_hour_count = sum(
        1 for e in events if datetime.fromisoformat(e["timestamp"]).hour == 3
    )

    assert business_hour_count > overnight_hour_count


def test_generated_events_use_only_the_requested_hosts():
    events = generate_dataset(days=2, hosts=["ONLY-HOST"])

    assert events  # sanity: the 2-day window actually produced events
    assert all(e["host_id"] == "ONLY-HOST" for e in events)


def test_generated_events_stay_within_the_requested_day_range():
    days = 3
    events = generate_dataset(days=days, hosts=["DESKTOP-001"])
    now = datetime.now(timezone.utc)

    for event in events:
        ts = datetime.fromisoformat(event["timestamp"])
        assert (now - ts).total_seconds() <= (days + 1) * 86400  # +1 day slack for the current partial hour


def test_network_events_carry_a_destination_ip():
    events = generate_dataset(days=5, hosts=["DESKTOP-001", "DESKTOP-002", "DESKTOP-003"])
    network_events = [e for e in events if e["log_type"] == "network"]

    assert network_events  # sanity: some network events were actually generated
    assert all(e.get("destination_ip") for e in network_events)


def test_generated_events_are_valid_normalized_logs():
    events = generate_dataset(days=1, hosts=["DESKTOP-001"])

    assert events
    for event in events:
        event = dict(event)
        event["tenant_id"] = "acme-corp"
        NormalizedLog(**event)  # raises on an invalid shape


def test_write_dataset_produces_one_json_object_per_line(tmp_path):
    events = generate_dataset(days=1, hosts=["DESKTOP-001"])
    output_path = tmp_path / "normal_behavior.jsonl"

    write_dataset(events, output_path)

    lines = output_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == len(events)
