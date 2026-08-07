"""
SafeSOC — Load/Performance Benchmark Tests (SS-066)
Covers the pure aggregation/statistics helpers in tests/perf/benchmark.py.
The benchmark's actual network calls are exercised live against a real
running backend (see the batch report) — this suite only proves the
math is correct, independent of any live server.
"""

from tests.perf.benchmark import _aggregate_ingestion_results, _compute_latency_stats


# ── _aggregate_ingestion_results ────────────────────────────────

def test_aggregate_ingestion_results_sums_accepted_across_batches():
    bodies = [{"accepted": 100, "rejected": 0}, {"accepted": 95, "rejected": 5}]

    result = _aggregate_ingestion_results(bodies, elapsed_seconds=2.0, total_events=200)

    assert result["accepted"] == 195
    assert result["failed_batches"] == 0
    assert result["events_per_second"] == 97.5


def test_aggregate_ingestion_results_counts_failed_batches_separately():
    bodies = [{"accepted": 100, "rejected": 0}, None, {"accepted": 50, "rejected": 0}]

    result = _aggregate_ingestion_results(bodies, elapsed_seconds=1.0, total_events=250)

    assert result["accepted"] == 150
    assert result["failed_batches"] == 1
    assert result["events_per_second"] == 150.0


def test_aggregate_ingestion_results_handles_zero_elapsed_time_without_dividing_by_zero():
    result = _aggregate_ingestion_results([{"accepted": 10}], elapsed_seconds=0.0, total_events=10)

    assert result["events_per_second"] == 0.0


def test_aggregate_ingestion_results_with_no_bodies_reports_zero_accepted():
    result = _aggregate_ingestion_results([], elapsed_seconds=1.0, total_events=0)

    assert result["accepted"] == 0
    assert result["failed_batches"] == 0


# ── _compute_latency_stats ───────────────────────────────────────

def test_compute_latency_stats_computes_mean_and_percentiles():
    # 10 evenly spaced values: 10, 20, ..., 100
    latencies = [float(i) * 10 for i in range(1, 11)]

    stats = _compute_latency_stats(latencies)

    assert stats["mean_ms"] == 55.0
    assert stats["max_ms"] == 100.0
    # p50 of a 10-element sorted list at index 10//2=5 -> the 6th value (60.0)
    assert stats["p50_ms"] == 60.0
    # p95 at index min(9, int(10*0.95)=9) -> the last (largest) value
    assert stats["p95_ms"] == 100.0


def test_compute_latency_stats_on_empty_input_returns_all_none():
    stats = _compute_latency_stats([])

    assert stats == {"mean_ms": None, "p50_ms": None, "p95_ms": None, "max_ms": None}


def test_compute_latency_stats_on_a_single_value():
    stats = _compute_latency_stats([42.0])

    assert stats["mean_ms"] == 42.0
    assert stats["p50_ms"] == 42.0
    assert stats["p95_ms"] == 42.0
    assert stats["max_ms"] == 42.0


def test_compute_latency_stats_does_not_mutate_the_input_list():
    latencies = [30.0, 10.0, 20.0]
    original = list(latencies)

    _compute_latency_stats(latencies)

    assert latencies == original
