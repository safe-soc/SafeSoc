# SafeSOC — Testing

## 1. Current State: Automated Backend Tests Exist (SS-002)

`backend/tests/` now contains a real suite: **545 tests** across 53 files, one per major module/feature (`test_schemas.py`, `test_ingestion.py`, `test_opensearch.py`, `test_exceptions.py`, `test_auth.py`/`test_auth_router.py`, `test_correlation.py`/`test_correlation_worker.py`, `test_incidents.py`/`test_incidents_router.py`, `test_investigation.py`/`test_investigate_router.py`, `test_anomaly.py`, `test_reporting.py`, `test_notifications.py`, `test_rate_limit.py`, `test_rbac.py`, `test_tenant_isolation.py`, and more), plus shared fixtures in `conftest.py`. `pytest`, `pytest-asyncio`, and `httpx` are in `backend/requirements.txt`. Run it:

```bash
cd backend
pytest
```

All 545 pass, offline — no live OpenSearch, Postgres, Redis, Docker, or network access required. External dependencies are mocked at their call sites (`mock_bulk_index_logs`, `mock_opensearch_unreachable`, and per-test Celery/Redis/HTTP mocks) rather than hitting live infrastructure.

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

Coverage now spans every implemented feature, not just the original SS-001–006 ingestion path:

| Area | Status | Test file(s) |
|---|---|---|
| Ingestion (`schemas/log.py`, `services/ingestion.py`, `routers/v1/ingest.py`) | **Covered** | `test_schemas.py`, `test_ingestion.py`, `test_adapters.py` |
| OpenSearch (`db/opensearch.py`) | **Covered** | `test_opensearch.py` |
| Auth (JWT, bcrypt, register/login/refresh, rate limiting) | **Covered** | `test_auth.py`, `test_auth_router.py`, `test_jwt.py`, `test_security.py`, `test_rate_limit.py`, `test_startup.py` |
| RBAC / tenant isolation | **Covered** | `test_rbac.py`, `test_dependencies.py`, `test_tenant_isolation.py` |
| Threat intel enrichment | **Covered** | `test_enrichment.py`, `test_enrichment_task.py`, `test_clients.py` |
| Correlation engine + MITRE mapping | **Covered** | `test_correlation.py`, `test_correlation_worker.py`, `test_mitre_mapping.py` |
| Risk scoring + endpoints | **Covered** | `test_risk_scoring.py`, `test_scoring_task.py`, `test_endpoints_router.py`, `test_models.py` |
| Incident management | **Covered** | `test_incidents.py`, `test_incidents_router.py` |
| CloudLens bridge | **Covered** | `test_cloud_router.py` |
| NL investigation assistant | **Covered** | `test_investigation.py`, `test_investigate_router.py`, `test_mcp_tools.py`, `test_ollama_client.py`, `test_groq_client.py` |
| Anomaly detection | **Covered** | `test_anomaly.py`, `test_ml_generate_training_data.py`, `test_ml_train.py` |
| Reporting | **Covered** | `test_reporting.py`, `test_reporting_task.py`, `test_reports_router.py` |
| Notifications (Telegram) | **Covered** | `test_notifications.py`, `test_notification_worker.py`, `test_telegram_client.py` |
| Real-time (WebSocket, Redis pub/sub) | **Covered** | `test_ws_router.py`, `test_realtime.py`, `test_redis.py` |
| Postgres engine/session | **Covered** | `test_postgresql.py` |
| Celery app/broker config | **Covered** | `test_celery_app.py` |
| Injector (scenarios, demo mode) | **Covered** | `test_injector_scenarios.py`, `test_injector_demo.py` |
| Load/performance benchmark math | **Covered** | `test_benchmark.py` |
| `routers/health.py`, `core/exceptions.py` | **Covered** | `test_exceptions.py` |
| `routers/v1/alerts.py` | Not covered | Query parameter bounds (`timerange_hours` 1–720, `size` 1–500) — left for a follow-up test issue |

`pytest` + `pytest-asyncio` + `httpx` (FastAPI `TestClient`) is the actual stack.

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

**SS-078:** see [`docs/performance-benchmarks.md`](performance-benchmarks.md) for the published, reproduction-step-documented version of this same harness, including a more recent measurement pass and the exact environment (host, Docker resources, data volume) each run was measured on.

## 6. Summary

| Test type | Status |
|---|---|
| Unit/integration tests (backend) | **545 tests, passing** across every implemented feature (see §4) — **runs in CI** on every push/PR |
| Unit/integration tests (CloudLens) | None exist |
| CI pipeline | `safesoc-backend` job runs install → import check → `pytest`; `cloudlens-*` jobs remain smoke checks (Django check, frontend lint/typecheck/build) — no CloudLens test suite exists yet |
| Manual verification | Performed for Phase 1 ingestion pipeline (per report), not reproducible from repo alone |
