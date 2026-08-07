"""
SafeSOC — Load/Performance Test Harness (SS-066)
Repeatable benchmark against a REAL running backend, measuring the
SRS's throughput (>=100 events/sec ingestion) and latency (<500ms
alert queries) targets with real numbers instead of the informal
~50ms/10-log observation docs/testing.md previously carried.

Deliberately NOT picked up by the normal `pytest` collection (this
file matches neither `test_*.py` nor `*_test.py`) — CI has no live
backend stack to run this against; it's a manual/Docker-verification
tool, same category as injector/demo.py. The pure aggregation/
statistics helpers below (_aggregate_ingestion_results,
_compute_latency_stats) ARE covered by backend/tests/test_benchmark.py.

Usage (needs a running backend + a valid JWT — SS-016 requires auth on
both endpoints this benchmarks):

    python backend/tests/perf/benchmark.py --token <JWT> [--base-url URL]
"""

import argparse
import asyncio
import statistics
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

import httpx


def _make_log(host_id: str) -> dict:
    return {
        "log_type": "authentication",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host_id": host_id,
        "host_ip": "192.168.1.50",
        "action": "failed_login",
        "description": "Load test event",
        "severity": "low",
    }


def _aggregate_ingestion_results(
    response_bodies: list[Optional[dict]], *, elapsed_seconds: float, total_events: int
) -> dict:
    """
    Pure aggregation over already-fetched response JSON bodies (None for
    any batch that failed outright) — separated from the network calls
    in benchmark_ingestion() so this math is testable without a live
    server (see test_benchmark.py).
    """
    accepted = sum(body.get("accepted", 0) for body in response_bodies if body is not None)
    failed_batches = sum(1 for body in response_bodies if body is None)
    return {
        "total_events": total_events,
        "accepted": accepted,
        "failed_batches": failed_batches,
        "elapsed_seconds": elapsed_seconds,
        "events_per_second": accepted / elapsed_seconds if elapsed_seconds > 0 else 0.0,
    }


def _compute_latency_stats(latencies_ms: list[float]) -> dict:
    """Pure percentile/summary math over a list of already-measured latencies — testable without a live server."""
    if not latencies_ms:
        return {"mean_ms": None, "p50_ms": None, "p95_ms": None, "max_ms": None}

    sorted_ms = sorted(latencies_ms)
    return {
        "mean_ms": statistics.mean(sorted_ms),
        "p50_ms": sorted_ms[len(sorted_ms) // 2],
        "p95_ms": sorted_ms[min(len(sorted_ms) - 1, int(len(sorted_ms) * 0.95))],
        "max_ms": sorted_ms[-1],
    }


async def benchmark_ingestion(client: httpx.AsyncClient, *, total_events: int, batch_size: int) -> dict:
    """Fire concurrent ingestion batches at POST /api/v1/ingest, measuring aggregate events/sec."""
    batches = []
    remaining = total_events
    while remaining > 0:
        size = min(batch_size, remaining)
        batches.append({"logs": [_make_log(f"LOAD-{uuid.uuid4().hex[:8]}") for _ in range(size)]})
        remaining -= size

    async def _send(batch: dict) -> Optional[dict]:
        try:
            response = await client.post("/api/v1/ingest", json=batch)
            return response.json() if response.status_code == 200 else None
        except httpx.HTTPError:
            return None

    start = time.perf_counter()
    response_bodies = await asyncio.gather(*(_send(b) for b in batches))
    elapsed = time.perf_counter() - start

    return _aggregate_ingestion_results(list(response_bodies), elapsed_seconds=elapsed, total_events=total_events)


async def benchmark_alert_queries(client: httpx.AsyncClient, *, request_count: int) -> dict:
    """Fire sequential GET /api/v1/alerts calls, measuring per-request latency (sequential so each measurement is a clean single-request round-trip, not contending with the others)."""
    latencies_ms = []
    successful = 0
    for _ in range(request_count):
        start = time.perf_counter()
        try:
            response = await client.get("/api/v1/alerts", params={"timerange_hours": 24, "size": 50})
        except httpx.HTTPError:
            continue
        elapsed_ms = (time.perf_counter() - start) * 1000
        if response.status_code == 200:
            successful += 1
            latencies_ms.append(elapsed_ms)

    stats = _compute_latency_stats(latencies_ms)
    return {"request_count": request_count, "successful": successful, **stats}


async def run(
    base_url: str, token: str, *, total_events: int, batch_size: int, query_count: int
) -> dict:
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx.AsyncClient(base_url=base_url, headers=headers, timeout=30.0) as client:
        ingestion_result = await benchmark_ingestion(client, total_events=total_events, batch_size=batch_size)
        query_result = await benchmark_alert_queries(client, request_count=query_count)
    return {"ingestion": ingestion_result, "alert_queries": query_result}


def format_report(results: dict) -> str:
    ingestion = results["ingestion"]
    queries = results["alert_queries"]

    lines = ["=== SafeSOC Load/Performance Benchmark ===", ""]
    lines.append("Ingestion throughput (SRS target: >=100 events/sec)")
    lines.append(
        f"  Accepted: {ingestion['accepted']}/{ingestion['total_events']} events "
        f"in {ingestion['elapsed_seconds']:.2f}s ({ingestion['failed_batches']} failed batches)"
    )
    lines.append(f"  Throughput: {ingestion['events_per_second']:.1f} events/sec")
    lines.append(f"  Result: {'PASS' if ingestion['events_per_second'] >= 100 else 'FAIL'}")

    lines.append("")
    lines.append("Alert query latency (SRS target: <500ms)")
    if queries["mean_ms"] is not None:
        lines.append(f"  Requests: {queries['successful']}/{queries['request_count']} successful")
        lines.append(
            f"  Mean: {queries['mean_ms']:.1f}ms  p50: {queries['p50_ms']:.1f}ms  "
            f"p95: {queries['p95_ms']:.1f}ms  max: {queries['max_ms']:.1f}ms"
        )
        lines.append(f"  Result: {'PASS' if queries['p95_ms'] < 500 else 'FAIL'} (p95 vs. 500ms target)")
    else:
        lines.append("  No successful queries.")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="SafeSOC load/performance benchmark (SS-066)")
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--token", required=True, help="A valid JWT — see docs/testing.md")
    parser.add_argument("--total-events", type=int, default=1000)
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--query-count", type=int, default=50)
    args = parser.parse_args()

    results = asyncio.run(
        run(
            args.base_url,
            args.token,
            total_events=args.total_events,
            batch_size=args.batch_size,
            query_count=args.query_count,
        )
    )
    print(format_report(results))


if __name__ == "__main__":
    main()
