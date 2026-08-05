# SafeSOC — System Architecture

Status legend: **Implemented** (working code in this repo) · **Stub** (file/module exists but is empty or a placeholder) · **Planned** (described in the Phase 1 report, no code yet).

## 1. Overview

SafeSOC is designed as a six-layer, service-oriented platform (per the Phase 1 report, §4.1). As of Phase 1, only the Source, part of the Ingestion, and part of the Storage layers are implemented. The Processing, full API, and Presentation layers are scaffolded as empty placeholder files but contain no logic yet. CloudLens (`cloud/`) is a separate, fully working application that is not yet wired into this pipeline.

```
┌─────────────────────────────────────────────────────────┐
│ 1. Source Layer         Endpoint agents · Cloud logs ·   │
│                          Network logs · Synthetic injector│
├─────────────────────────────────────────────────────────┤
│ 2. Ingestion Layer       Adapters · Normalize · Validate ·│
│                          FastAPI ingest endpoint · Bulk   │
├─────────────────────────────────────────────────────────┤
│ 3. Processing Layer      Correlation · NL Assistant ·     │
│                          Anomaly Detection · Risk Scoring │
├─────────────────────────────────────────────────────────┤
│ 4. Storage Layer         OpenSearch · PostgreSQL · Redis  │
├─────────────────────────────────────────────────────────┤
│ 5. API Layer             REST (FastAPI) · WebSockets      │
├─────────────────────────────────────────────────────────┤
│ 6. Presentation Layer    React dashboard                  │
└─────────────────────────────────────────────────────────┘
```

## 2. Layer-by-Layer Status

### 2.1 Source Layer

| Source | Status | Notes |
|---|---|---|
| Synthetic log injector | **Implemented** | `injector/injector.py` — generates random `authentication`-type logs and POSTs them to `/api/v1/ingest`. |
| Wazuh endpoint agents | **Planned** | `LogSource.WAZUH` exists as an enum value (`backend/app/core/enums.py`); no adapter reads real Wazuh output. |
| AWS CloudTrail / GuardDuty | **Planned** | Enum values exist (`AWS_CLOUDTRAIL`, `AWS_GUARDDUTY`); no adapter or feed exists. |
| Network logs | **Planned** | No source or schema support beyond the generic `network` `log_type`. |

### 2.2 Ingestion Layer

| Component | Status | File |
|---|---|---|
| Ingestion API (`POST /api/v1/ingest`) | **Implemented** | `backend/app/routers/v1/ingest.py` |
| Schema validation (`NormalizedLog`) | **Implemented** | `backend/app/schemas/log.py` |
| Bulk write to OpenSearch | **Implemented** | `backend/app/db/opensearch.py` |
| Source-specific adapters (Wazuh, CloudTrail, GuardDuty) | **Stub** | `backend/app/adapters/__init__.py` is empty; only the `synthetic` path is exercised today (the ingest endpoint defaults `source` to `"synthetic"` and does no per-source transformation). |
| Async processing / batch buffering beyond OpenSearch's own bulk API | **Planned** | No queue or worker consumes ingestion events yet. |

### 2.3 Processing Layer

All of the following are **empty placeholder files** — the module exists on disk with the intended filename but contains no logic:

| Capability | Intended file | Status |
|---|---|---|
| Threat intelligence enrichment | `backend/app/services/enrichment.py`, `backend/app/clients/{virustotal,abuseipdb}.py` | Stub |
| Attack chain correlation engine | `backend/app/services/correlation.py`, `backend/app/workers/correlation_worker.py` | Stub |
| Anomaly detection (Isolation Forest) | `backend/app/services/anomaly.py`, `ml/` (directory is empty) | Stub |
| Endpoint risk scoring | `backend/app/services/risk_scoring.py`, `backend/app/tasks/scoring.py` | Stub |
| Natural language investigation assistant (MCP) | `backend/app/services/investigation.py`, `backend/app/mcp/__init__.py`, `backend/app/routers/v1/investigate.py` | Stub |
| Automated PDF reporting | `backend/app/services/reporting.py`, `backend/app/tasks/reporting.py` | Stub |
| Notifications | `backend/app/services/notifications.py`, `backend/app/workers/notification_worker.py`, `backend/app/clients/telegram.py` | Stub |

`backend/app/core/config.py` already defines the settings these components will need (rate limits, cache TTLs, risk-score weights, correlation window TTL, LLM provider config), but nothing reads them yet.

### 2.4 Storage Layer

| Store | Status | Notes |
|---|---|---|
| OpenSearch | **Implemented** | Single index pattern `safesoc-alerts-{YYYY}.{MM}`, mapping in `backend/app/db/mappings/alert_mapping.py`, client/bulk-write/search logic in `backend/app/db/opensearch.py`. |
| PostgreSQL | **Planned** | `backend/app/db/postgresql.py` is an empty stub. No SQLAlchemy models exist (`backend/app/models/__init__.py` is empty). `backend/migrations/versions/` contains only a `.gitkeep` — no Alembic migrations have been generated, despite `alembic.ini` being present at the backend root. |
| Redis | **Planned** | `backend/app/db/redis.py` is an empty stub. Nothing uses it. |

### 2.5 API Layer

| Endpoint | Status |
|---|---|
| `GET /` | **Implemented** — root info (`backend/app/main.py`) |
| `GET /health` | **Implemented** — checks OpenSearch only; Postgres/Redis checks are noted as future additions directly in the code comment |
| `POST /api/v1/ingest` | **Implemented** |
| `GET /api/v1/alerts` | **Implemented** |
| `routers/v1/auth.py` | **Stub** — no login/JWT endpoints exist yet, despite JWT settings being defined in config |
| `routers/v1/cloud.py` | **Stub** — no bridge to CloudLens findings |
| `routers/v1/endpoints.py` | **Stub** — no endpoint/risk-score views |
| `routers/v1/incidents.py` | **Stub** — no incident lifecycle endpoints |
| `routers/v1/investigate.py` | **Stub** — no NL assistant endpoint |
| `routers/v1/reports.py` | **Stub** — no report download endpoint |
| WebSocket channel for live dashboard updates | **Planned** — not present anywhere in `main.py` |

Full interactive documentation for the implemented endpoints is available at `/docs` (Swagger UI, enabled when `DEBUG=True`) once the backend is running.

### 2.6 Presentation Layer

`frontend/` contains only a `.gitkeep` file — no React application exists yet. This layer is entirely **Planned**.

## 3. CloudLens (Cloud Security Module)

CloudLens (`cloud/AWS-IAM-backend` + `cloud/AWS-IAM-frontend`) is a **separate, working application**, not a module inside the SafeSOC backend:

- Django 5 + DRF backend (`cloud/AWS-IAM-backend`) with a real IAM scanning engine: `engine/scanner.py`, `engine/graph_builder.py`, `engine/risk_rules.py`, `engine/iam_normalize.py`, `engine/aws_wrapper.py`, `engine/notifier.py` (Telegram) — all contain real logic (~575 lines total).
- React + TypeScript frontend (`cloud/AWS-IAM-frontend`) with a dashboard, graph explorer, risk findings, and settings pages (~1,145 lines total).
- Its own `docker-compose.yml` at `cloud/docker-compose.yml`, independent of the SafeSOC backend's deployment.

**Integration status: Planned.** Per the Phase 1 report (§6.4, §7.4), CloudLens findings are intended to be adapted to the `NormalizedLog` schema and pushed through the same `/api/v1/ingest` pipeline so cloud findings appear in the unified alert queue. No code implementing this bridge exists yet — `routers/v1/cloud.py` in the SafeSOC backend is an empty stub.

## 4. Multi-Tenancy

The report describes tenant isolation enforced at the database query layer with JWT-based auth. Today:

- `tenant_id` is a required field on `NormalizedLog` and is used as a mandatory filter in `search_alerts()` (`backend/app/db/opensearch.py`) — **Implemented** at the data-model level.
- Tenant ID is currently taken directly from the request body (`payload.get("tenant_id", "default-tenant")` in `ingest.py`) rather than derived from an authenticated JWT — there is no authentication layer yet, so tenant isolation is **not enforced**; any caller can write or read any tenant's data by passing a different `tenant_id`. This is a Phase 2 requirement (`routers/v1/auth.py` stub, `core/security.py` stub).

## 5. Summary Table

| Layer | Implementation state |
|---|---|
| Source | Synthetic only |
| Ingestion | Core pipeline implemented; adapters stubbed |
| Processing | Entirely stubbed |
| Storage | OpenSearch implemented; PostgreSQL/Redis stubbed |
| API | 4 of ~10 planned endpoint groups implemented |
| Presentation | Not started |
| CloudLens | Fully working standalone; not integrated |
