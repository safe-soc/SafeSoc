# SafeSOC — Performance Benchmarks

SS-078. A published, reproducible record of `backend/tests/perf/benchmark.py`'s (SS-066) measured results, run against a real, running SafeSOC stack — not a one-off number quoted without a way to check it. See `docs/testing.md` for how this fits alongside the automated `pytest` suite (this harness is deliberately separate from it — it needs a live backend, which CI doesn't provide).

## SRS Targets

| Metric | Target | Measured (see below) |
|---|---|---|
| Ingestion throughput | ≥ 100 events/sec | 795–1,531 events/sec |
| Alert query latency (p95) | < 500ms | 128–148ms |

Both targets pass with wide margin across every run recorded here.

## How to Reproduce This Yourself

1. Start the stack (`./scripts/install.sh` / `./scripts/install.ps1`, or `docker compose up --build`).
2. Get a JWT for any tenant — the fastest path is the demo tenant:
   ```bash
   python injector/demo.py
   # prints demo@safesoc.example / SafeSOC-Demo-2026! — log in with it:
   curl -X POST http://localhost:8000/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{"tenant_id":"00000000-dead-beef-0000-000000000001","email":"demo@safesoc.example","password":"SafeSOC-Demo-2026!"}'
   ```
3. Run the benchmark from `backend/`:
   ```bash
   cd backend
   python tests/perf/benchmark.py --token <JWT>
   ```
   Optional flags: `--base-url` (default `http://localhost:8000`), `--total-events` (default 1000), `--batch-size` (default 100), `--query-count` (default 50).

The harness fires concurrent `POST /api/v1/ingest` batches to measure throughput, then sequential `GET /api/v1/alerts` calls to measure per-request latency (sequential so each measurement is a clean round-trip, not contending with the others for the same connection pool). Its pure aggregation/percentile math (`_aggregate_ingestion_results`, `_compute_latency_stats`) is covered by `backend/tests/test_benchmark.py` and runs in CI; the live run above does not (no live backend exists in CI).

## Measured Results

Two consecutive runs, same command (`--total-events 1000 --batch-size 100 --query-count 50`), same running stack, no changes in between — to show the range rather than a single cherry-picked number:

| Run | Ingestion throughput | Ingestion result | Query mean | Query p50 | Query p95 | Query max | Latency result |
|---|---|---|---|---|---|---|---|
| 1 | 795.4 events/sec | PASS | 100.3ms | 99.6ms | 147.8ms | 212.8ms | PASS |
| 2 | 1,531.1 events/sec | PASS | 101.1ms | 97.8ms | 128.7ms | 310.1ms | PASS |

Both runs: 1000/1000 events accepted, 0 failed batches, 50/50 alert queries successful.

## Environment These Numbers Were Measured On

Numbers vary by hardware, Docker resource allocation, and host load — quoted here for reproducibility, not as a universal guarantee:

- **Host:** Windows 11, Docker Desktop (WSL2 backend)
- **Docker:** Server `linux/amd64`, version 28.4.0
- **Resources allocated to Docker:** 12 CPUs, ~7.9GB memory
- **Stack:** the standard 6-service `docker-compose.yml` (OpenSearch 2.x, PostgreSQL 16, Redis 7, backend, worker, beat) — a local dev/demo setup, not a production deployment (single OpenSearch node, no separate DB/app hosts, shared machine also running other software during the measurement)
- **Python:** 3.13.3 (benchmark client); backend runs 3.12-slim in its container (`backend/Dockerfile`)
- **Data volume at time of measurement:** a demo tenant with ~86 pre-existing incidents and thousands of alerts from prior sessions' activity — not an empty database, so these numbers already reflect realistic-ish background load, not a pristine best case.

A dedicated benchmarking host with no other workload, a production-sized OpenSearch cluster, or a much larger existing dataset would all produce different numbers — reproduce the steps above against your own environment rather than treating the table as universal.

## History

| Date | Context |
|---|---|
| 2026-08-25 (SS-066) | First live measurement: 452–582 events/sec, 130–159ms p95 (see `CHANGELOG.md` v0.12.0-alpha) |
| 2026-08-26 (SS-078) | This document's measurements: 795–1,531 events/sec, 128–148ms p95 |

Both passes measured against a live stack with real accumulated demo data, not a synthetic empty-database best case — the throughput increase between passes most likely reflects host/Docker resource availability at measurement time rather than a code change (no ingestion-path code changed between SS-066 and this pass).
