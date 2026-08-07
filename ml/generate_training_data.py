"""
SafeSOC — Synthetic Normal-Behavior Training Data Generator (SS-048)
Generates ~30 days of "normal" synthetic security events with realistic
diurnal (hour-of-day) and weekly (weekday-vs-weekend) volume patterns,
for the Isolation Forest anomaly model (SS-049, ml/train.py) to learn
what "normal" looks like from — unsupervised training needs structure
in the data, not uniformly random noise.

Distinct from injector/injector.py's live HTTP-posting role (and from
the attack-scenario simulation added in Milestone 13): this writes a
static training dataset to disk. It reuses injector.py's host/user/
action pools and generate_log() rather than duplicating them.

Usage:
    python ml/generate_training_data.py [output_path] [days]

Rerun whenever the host pool or event shape changes; ml/train.py
(SS-049) reads whatever dataset is on disk at DEFAULT_OUTPUT_PATH.
"""

import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from injector.injector import ACTIONS, USERS, generate_log  # noqa: E402

DEFAULT_OUTPUT_PATH = Path(__file__).resolve().parent / "data" / "normal_behavior.jsonl"
TRAINING_DAYS = 30

# A dedicated, smaller host pool for training data — independent of
# injector.py's 50-host HOSTS pool, since generating 30 days of traffic
# for that many hosts isn't needed to give an Isolation Forest enough
# structure to learn from, and would make the dataset unnecessarily large.
TRAINING_HOSTS = [f"DESKTOP-{i:03d}" for i in range(1, 11)]

BASE_EVENTS_PER_HOUR = 3  # per host, at the least-busy hour of the week

# Business-hours multiplier per hour of day (0-23), weekday, roughly
# shaped like a real office: quiet overnight, ramping up into the
# 9-to-5, winding down in the evening. Deliberately NOT flat/uniform —
# an Isolation Forest trained on uniform noise has no "normal" shape to
# contrast anomalies against (AC).
_WEEKDAY_HOURLY_MULTIPLIER = (
    0.2, 0.15, 0.15, 0.15, 0.2, 0.3,  # 00-05: overnight
    0.6, 1.2, 2.5, 3.0, 3.0, 2.8,     # 06-11: ramp into business hours
    2.5, 2.8, 3.0, 3.0, 2.8, 2.2,     # 12-17: business hours
    1.2, 0.8, 0.5, 0.4, 0.3, 0.25,    # 18-23: wind-down
)
_WEEKEND_MULTIPLIER = 0.35  # weekends are quieter overall, but not silent

# Most "normal" network activity stays inside the LAN; a smaller share
# reaches out to the internet (DNS, web, updates) — gives the
# distinct-destination-IP feature (SS-050) real variation to learn from.
_INTERNAL_DESTINATION_WEIGHT = 0.8


def _expected_events(hour: int, weekday: int) -> float:
    """Expected event count for one host in one hour, given diurnal + weekly patterns."""
    multiplier = _WEEKDAY_HOURLY_MULTIPLIER[hour]
    if weekday >= 5:  # Saturday=5, Sunday=6
        multiplier *= _WEEKEND_MULTIPLIER
    return BASE_EVENTS_PER_HOUR * multiplier


def _sample_count(expected: float) -> int:
    """
    Normal approximation to a Poisson(expected) draw, clipped at 0.
    Close enough to Poisson-shaped for training-data purposes without
    pulling in numpy/scipy as a dependency just for this.
    """
    if expected <= 0:
        return 0
    return max(0, round(random.gauss(expected, expected**0.5)))


def _random_destination_ip() -> str:
    if random.random() < _INTERNAL_DESTINATION_WEIGHT:
        return f"192.168.1.{random.randint(2, 254)}"
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def generate_dataset(days: int = TRAINING_DAYS, hosts: Optional[list[str]] = None) -> list[dict]:
    """
    Generate `days` days of realistic normal-behavior events for `hosts`
    (defaults to TRAINING_HOSTS), with per-host, per-hour event counts
    driven by _expected_events()'s diurnal/weekly curve rather than
    uniform randomness (AC).
    """
    hosts = hosts or TRAINING_HOSTS
    end = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    start = end - timedelta(days=days)

    events: list[dict] = []
    current = start
    while current < end:
        expected = _expected_events(current.hour, current.weekday())
        for host in hosts:
            for _ in range(_sample_count(expected)):
                log_type = random.choice(list(ACTIONS.keys()))
                event = generate_log(log_type=log_type, severity="low", host_id=host)
                event["timestamp"] = (
                    current + timedelta(minutes=random.uniform(0, 59), seconds=random.uniform(0, 59))
                ).isoformat()
                event["user"] = random.choice(USERS)
                if log_type == "network":
                    event["destination_ip"] = _random_destination_ip()
                events.append(event)
        current += timedelta(hours=1)

    return events


def write_dataset(events: list[dict], output_path: Path = DEFAULT_OUTPUT_PATH) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")


def main():
    output_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUTPUT_PATH
    days = int(sys.argv[2]) if len(sys.argv) > 2 else TRAINING_DAYS

    events = generate_dataset(days=days)
    write_dataset(events, output_path)
    print(f"Generated {len(events)} normal-behavior events across {days} days -> {output_path}")


if __name__ == "__main__":
    main()
