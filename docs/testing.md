# SafeSOC — Testing

## 1. Current State: No Automated Tests Exist

`backend/tests/` contains exactly two files:

| File | Contents |
|---|---|
| `__init__.py` | Empty |
| `conftest.py` | Empty — no pytest fixtures defined |

There are **zero test cases** in the repository for the SafeSOC backend. `pytest` (or any test runner) is not in `backend/requirements.txt`. `.github/workflows/ci.yml` exists but is empty, so no tests run automatically on push/PR either.

This should be read plainly: the Phase 1 report's "end-to-end tested ingestion pipelines with full schema compliance" (Abstract, §6.2) refers to **manual verification**, not an automated test suite. That distinction matters for anyone extending the code — there is no regression safety net yet.

## 2. How Phase 1 Was Actually Verified (Manual)

Per the report's Results chapter (§6.2) and what the code supports:

1. **Health check** — `GET /health` confirming OpenSearch connectivity.
2. **Swagger UI** (`/docs`) — manual, interactive exercise of `POST /api/v1/ingest` and `GET /api/v1/alerts`.
3. **Synthetic injector** (`injector/injector.py`) — used to generate batches of logs and visually confirm they show up via the alerts endpoint.
4. **Docker Compose screenshot evidence** (report Figures 5.1, 5.2, 6.1, 6.2) — confirms the containers ran and responded at the time, not a repeatable test.

None of this is captured as code that can be re-run to catch a regression.

## 3. CloudLens Testing

`cloud/AWS-IAM-backend` and `cloud/AWS-IAM-frontend` also have no dedicated test directories or test dependencies declared. The report states CloudLens was "validated against a live AWS environment" (§6.3) — again, this describes manual validation, not an automated suite.

## 4. What Should Exist (Planned)

Given the implemented surface area (ingestion, alerts, health, OpenSearch client, schema validation), the following are the natural first automated tests once a test runner is added:

| Area | Suggested coverage |
|---|---|
| `schemas/log.py` | Valid `NormalizedLog` construction; rejection of missing required fields (`tenant_id`, `host_id`, `severity`, etc.) |
| `services/ingestion.py` | Batch with mixed valid/invalid logs → correct `accepted`/`rejected` counts; `tenant_id`/`source` default injection |
| `routers/v1/ingest.py` | `422` on payload missing both `log` and `logs`; `422` when `logs` is not a list |
| `db/opensearch.py` | Monthly index name generation (`_build_index_name`) across month/year boundaries; mocked bulk-write error handling |
| `routers/v1/alerts.py` | Query parameter validation bounds (`timerange_hours` 1–720, `size` 1–500) |
| `routers/health.py` | Degraded status when OpenSearch is unreachable |

Recommended (not yet decided): `pytest` + `pytest-asyncio` + `httpx` (FastAPI `TestClient`) for the backend; a mocked/ephemeral OpenSearch (e.g. `testcontainers`) for integration-level tests against `db/opensearch.py`.

## 5. Non-Functional Testing (Planned)

The SRS's throughput target (≥100 events/sec) and latency targets (<500ms alert queries, <15s NL assistant) have no corresponding load or performance tests in the repo. The report's ~50ms figure for 10-log batches (§6.2) was an informal, manual observation, not a benchmark harness.

## 6. Summary

| Test type | Status |
|---|---|
| Unit tests (backend) | None exist |
| Integration tests (backend) | None exist |
| Unit/integration tests (CloudLens) | None exist |
| CI pipeline | Workflow file present, empty — no steps configured |
| Manual verification | Performed for Phase 1 ingestion pipeline (per report), not reproducible from repo alone |
