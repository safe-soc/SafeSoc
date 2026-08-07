# SafeSOC — Testing

## 1. Current State: Automated Backend Tests Exist (SS-002)

`backend/tests/` now contains a real suite: 37 tests across `test_schemas.py`, `test_ingestion.py`, `test_opensearch.py`, and `test_exceptions.py`, plus shared fixtures in `conftest.py`. `pytest`, `pytest-asyncio`, and `httpx` are in `backend/requirements.txt`. Run it:

```bash
cd backend
pytest
```

All 37 pass, offline — no live OpenSearch, Docker, or network access required. OpenSearch interactions are mocked (`mock_bulk_index_logs`, `mock_opensearch_unreachable` fixtures in `conftest.py`) rather than hitting a real cluster.

**Now automatic:** `.github/workflows/ci.yml`'s `safesoc-backend` job runs this suite (`pytest`, after the install and import-check steps) on every push/PR — a failing test fails the build (SS-003).

This should still be read carefully: the Phase 1 report's "end-to-end tested ingestion pipelines with full schema compliance" (Abstract, §6.2) referred to **manual verification**, not this suite (which postdates the report). The two are separate claims.

## 2. How Phase 1 Was Actually Verified (Manual)

Per the report's Results chapter (§6.2) and what the code supports:

1. **Health check** — `GET /health` confirming OpenSearch connectivity.
2. **Swagger UI** (`/docs`) — manual, interactive exercise of `POST /api/v1/ingest` and `GET /api/v1/alerts`.
3. **Synthetic injector** (`injector/injector.py`) — used to generate batches of logs and visually confirm they show up via the alerts endpoint.
4. **Docker Compose screenshot evidence** (report Figures 5.1, 5.2, 6.1, 6.2) — confirms the containers ran and responded at the time, not a repeatable test.

None of this is captured as code that can be re-run to catch a regression.

## 3. CloudLens Testing

`cloud/AWS-IAM-backend` and `cloud/AWS-IAM-frontend` also have no dedicated test directories or test dependencies declared. The report states CloudLens was "validated against a live AWS environment" (§6.3) — again, this describes manual validation, not an automated suite.

## 4. Current Coverage vs. Remaining Gaps

| Area | Status | Notes |
|---|---|---|
| `schemas/log.py` | **Covered** | Valid construction, defaults, auto-generated `alert_id`, rejection of each of the 9 required fields individually, invalid enum values, the schema's own documented example |
| `services/ingestion.py` | **Covered** | All-valid batch, mixed valid/invalid (partial failure), all-invalid (no write attempted), empty batch, `tenant_id`/`source` default injection |
| `db/opensearch.py` (`_build_index_name`) | **Covered** | Month padding, December/January year boundaries, default-to-current-time |
| `db/opensearch.py` (`check_connection`) | **Covered** | Ping succeeds, ping returns `False`, client construction raises |
| `routers/health.py` (`GET /health`) | **Covered** | Both degraded (OpenSearch unreachable) and healthy (connected) responses, via `TestClient` |
| `core/exceptions.py` (`safesoc_exception_handler`) | **Covered** | Documented `{"error", "status_code"}` shape for both `IngestionError` (422) and `OpenSearchError` (503), via an isolated test app; end-to-end wiring proven via the two `routers/v1/ingest.py` cases below (SS-004) |
| `routers/v1/ingest.py` | **Covered** | `422` on payload missing both `log`/`logs`; `422` when `logs` isn't a list; `INGEST_BATCH_SIZE` cap — exactly-at-limit accepted, one-over-limit rejected with no write attempted (SS-005) — all assert the typed-exception response body, not just the status code |
| `routers/v1/alerts.py` | Not covered | Query parameter bounds (`timerange_hours` 1–720, `size` 1–500) — left for a follow-up test issue |

`pytest` + `pytest-asyncio` + `httpx` (FastAPI `TestClient`) is now the actual stack, not just a recommendation.

## 5. Non-Functional Testing (SS-066)

A repeatable load/performance benchmark now exists: `backend/tests/perf/benchmark.py`. It's a standalone script, not part of the `pytest` suite CI runs (CI has no live backend stack to benchmark against) — the pure aggregation/percentile math it uses is covered by `backend/tests/test_benchmark.py` instead. Run it against a real running stack:

```bash
python backend/tests/perf/benchmark.py --token <a valid JWT> [--base-url http://localhost:8000]
```

**Measured results** (Docker Compose, default resource limits, 2026-08-08 — two runs, to confirm the numbers are repeatable, not a one-off):

| Target (SRS) | Run 1 | Run 2 | Result |
|---|---|---|---|
| Ingestion ≥100 events/sec | 582.3 events/sec (1000 events, 1.72s, 0 failed batches) | 452.8 events/sec (1000 events, 2.21s, 0 failed batches) | **PASS** — 4.5–5.8x the target |
| Alert queries <500ms | p50 98.6ms / p95 158.7ms / max 182.8ms (50/50 successful) | p50 73.7ms / p95 130.7ms / max 234.6ms (50/50 successful) | **PASS** — p95 well under target both runs |

The NL assistant's <15s target is separately measured in `docs/api-design.md`'s `POST /api/v1/investigate` section (SS-047) — not part of this benchmark, since it depends on LLM availability rather than ingestion/query throughput.

These numbers describe a single-node Docker Compose dev setup, not a production deployment — re-run this benchmark against the actual target environment before relying on it for capacity planning.

## 6. Summary

| Test type | Status |
|---|---|
| Unit/integration tests (backend) | **37 tests, passing** (`schemas`, `services/ingestion`, `db/opensearch`, `routers/health`, `core/exceptions` + `routers/v1/ingest` error paths incl. batch-size cap) — **runs in CI** on every push/PR |
| Unit/integration tests (CloudLens) | None exist |
| CI pipeline | `safesoc-backend` job runs install → import check → `pytest`; `cloudlens-*` jobs remain smoke checks (Django check, frontend lint/typecheck/build) — no CloudLens test suite exists yet |
| Manual verification | Performed for Phase 1 ingestion pipeline (per report), not reproducible from repo alone |
