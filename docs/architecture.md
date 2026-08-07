# SafeSOC — System Architecture

Status legend: **Implemented** (working code in this repo) · **Stub** (file/module exists but is empty or a placeholder) · **Planned** (described in the Phase 1 report, no code yet).

## 1. Overview

SafeSOC is designed as a six-layer, service-oriented platform (per the Phase 1 report, §4.1). As of SS-068 (Milestone 14), all six layers are implemented — Source, Ingestion, Processing, Storage, API, and Presentation. CloudLens (`cloud/`) is a separate, working application, bridged into this pipeline via `POST /api/v1/cloud/findings`.

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
| Synthetic log injector | **Implemented** | `injector/injector.py` — 6 named attack scenarios (`SCENARIOS`, SS-064) plus randomized default logs, authenticates before sending (BUG-001). `injector/demo.py` (SS-065) provisions a full demo tenant in one command. |
| Wazuh endpoint agents | **Implemented** | `backend/app/adapters/wazuh.py::transform()` converts real Wazuh alert JSON into `NormalizedLog`-shaped fields (SS-018). |
| AWS CloudTrail / GuardDuty | **Implemented** | `backend/app/adapters/{cloudtrail,guardduty}.py` (SS-019, SS-020). |
| CloudLens findings | **Implemented** | `backend/app/adapters/cloudlens.py` converts a CloudLens `Finding` into `NormalizedLog`-shaped fields (SS-038), pushed via `POST /api/v1/cloud/findings` (SS-039). |
| Network logs | **Partial** | No dedicated source/adapter; supported via the generic `network` `log_type` on any of the above sources. |

### 2.2 Ingestion Layer

| Component | Status | File |
|---|---|---|
| Ingestion API (`POST /api/v1/ingest`) | **Implemented** | `backend/app/routers/v1/ingest.py` — JWT-required (SS-016), rate-limited batch size (`INGEST_BATCH_SIZE`, SS-005) |
| Schema validation (`NormalizedLog`) | **Implemented** | `backend/app/schemas/log.py` |
| Bulk write to OpenSearch | **Implemented** | `backend/app/db/opensearch.py` |
| Source-specific adapters (Wazuh, CloudTrail, GuardDuty, CloudLens) | **Implemented** | Each exposes `transform(raw) -> dict`; `services/ingestion.py::ADAPTER_REGISTRY` dispatches a batch to the matching adapter based on its `source` field before schema validation (SS-021). `source: "synthetic"` (the default) skips adapter dispatch; an unrecognized `source` fails with `422`. |
| Async post-ingest processing | **Implemented** | Every accepted log queues three Celery background tasks — enrichment (SS-026), correlation (SS-030), critical-alert notification (SS-056) — via FastAPI `BackgroundTasks`, so none of them delay the ingestion response (ADR-005). |

### 2.3 Processing Layer

| Capability | File(s) | Status |
|---|---|---|
| Threat intelligence enrichment | `services/enrichment.py`, `clients/{virustotal,abuseipdb}.py`, `tasks/enrichment.py` | **Implemented** (SS-022–026) — Postgres-cached (`models/ti_cache.py`), runs async post-ingest |
| Attack chain correlation engine | `services/correlation.py`, `workers/correlation_worker.py` | **Implemented** (SS-027–031) — 6 pattern detectors over a Redis sliding window per tenant+host, MITRE ATT&CK mapping, auto-creates/merges incidents |
| Endpoint risk scoring | `services/risk_scoring.py`, `tasks/scoring.py` | **Implemented** (SS-032–033) — scored from alert history with time decay, re-scored on a schedule via Celery beat |
| Natural language investigation assistant | `services/investigation.py`, `mcp/tools.py`, `routers/v1/investigate.py`, `clients/{ollama,groq}.py` | **Implemented** (SS-042–047) — 8-intent classification, MCP tool calls into existing services, Redis-backed conversation context, LLM-generated answers bounded to the SRS's 15s target |
| Anomaly detection | `services/anomaly.py`, `ml/train.py`, `ml/model/isolation_forest.pkl` | **Implemented** (SS-048–051) — Isolation Forest over a 7-feature vector plus a Z-score network-volume-spike detector |
| Automated PDF reporting | `services/reporting.py`, `tasks/reporting.py` | **Implemented** (SS-052–054) — weekly digest via WeasyPrint, Celery-beat scheduled, listed/downloaded via `GET /api/v1/reports` |
| Notifications | `services/notifications.py`, `workers/notification_worker.py`, `clients/telegram.py` | **Implemented** (SS-055–056) — Telegram, gated on critical severity for per-alert notifications and unconditional for detected attack chains; no-ops silently if unconfigured |

`backend/app/core/config.py` defines the settings all of the above consume (rate limits, cache TTLs, risk-score weights, correlation window TTL, LLM provider config, auth rate limits) — see `docs/security-review.md` for the SS-067 additions.

### 2.4 Storage Layer

| Store | Status | Notes |
|---|---|---|
| OpenSearch | **Implemented** | Single index pattern `safesoc-alerts-{YYYY}.{MM}`, mapping in `backend/app/db/mappings/alert_mapping.py`, client/bulk-write/search logic in `backend/app/db/opensearch.py`, ILM retention (SS-006). |
| PostgreSQL | **Implemented** | `backend/app/db/postgresql.py` — async engine/session factory (SS-007). Models: `Tenant`, `User`, `Incident`, `IncidentNote`, `IncidentStateTransition`, `TICache`, `Endpoint` (SS-009, SS-024, SS-035). Alembic migrations under `backend/migrations/versions/`. |
| Redis | **Implemented** | `backend/app/db/redis.py` (SS-010). Used for: correlation sliding windows (SS-027), investigation session context (SS-046), real-time pub/sub event bus (SS-063), and auth rate-limit counters (SS-067). |

### 2.5 API Layer

| Endpoint | Status |
|---|---|
| `GET /` | **Implemented** — root info (`backend/app/main.py`) |
| `GET /health` | **Implemented** — checks OpenSearch connectivity |
| `POST /api/v1/ingest` | **Implemented** — JWT-required |
| `GET /api/v1/alerts` | **Implemented** — JWT-required |
| `POST /api/v1/auth/register`, `/login`, `/refresh` | **Implemented** (SS-012–014) — bcrypt hashing, JWT issuance, rate-limited (SS-067) |
| `POST /api/v1/cloud/findings`, `GET /api/v1/cloud/summary` | **Implemented** (SS-039–040) — service-token authenticated |
| `GET /api/v1/endpoints` | **Implemented** (SS-034) — risk-sorted |
| `routers/v1/incidents.py` | **Implemented** (SS-036–037) — full CRUD, lifecycle transitions, alert linking, notes |
| `POST /api/v1/investigate` | **Implemented** (SS-047) |
| `GET /api/v1/reports`, `GET /api/v1/reports/{filename}` | **Implemented** (SS-054) |
| `GET /ws?token=<JWT>` | **Implemented** (SS-063) — WebSocket, pushes new-alert/chain-detected events over Redis pub/sub |

No stub routers remain. Full interactive documentation is available at `/docs` (Swagger UI, enabled when `DEBUG=True`) while the backend is running; see `docs/api-design.md` for the full contract.

### 2.6 Presentation Layer

`frontend/` is a React 18 + TypeScript + Vite + Tailwind application (SS-057), matching CloudLens's stack: login/auth, alert queue, endpoint risk dashboard, incident management, investigation chat, and real-time updates over the SS-063 WebSocket (SS-058–063). **Implemented.**

## 3. CloudLens (Cloud Security Module)

CloudLens (`cloud/AWS-IAM-backend` + `cloud/AWS-IAM-frontend`) is a **separate, working application**, not a module inside the SafeSOC backend:

- Django 5 + DRF backend (`cloud/AWS-IAM-backend`) with a real IAM scanning engine: `engine/scanner.py`, `engine/graph_builder.py`, `engine/risk_rules.py`, `engine/iam_normalize.py`, `engine/aws_wrapper.py`, `engine/notifier.py` (Telegram).
- React + TypeScript frontend (`cloud/AWS-IAM-frontend`) with a dashboard, graph explorer, risk findings, and settings pages.
- Its own `docker-compose.yml` at `cloud/docker-compose.yml`, independent of the SafeSOC backend's deployment.

**Integration status: Implemented.** `cloud/AWS-IAM-backend/engine/safesoc_bridge.py` pushes each scan's findings to SafeSOC's `POST /api/v1/cloud/findings` (service-token authenticated, `CLOUDLENS_SERVICE_TOKEN`) after a scan completes (SS-039); `backend/app/adapters/cloudlens.py` converts them to `NormalizedLog` shape (SS-038) and routes them through the same ingestion pipeline every other source uses — enrichment, correlation, and risk scoring all apply equally to cloud-sourced alerts. `GET /api/v1/cloud/summary` (SS-040) adds cloud-specific aggregate stats; `docs/decisions.md` ADR-009 documents the decision to keep CloudLens's own risk score separate from SafeSOC's risk scoring rather than unify them (SS-041).

## 4. Multi-Tenancy

Tenant isolation is enforced at both the query layer and the auth layer:

- `tenant_id` is a required field on `NormalizedLog` and is used as a mandatory filter in `search_alerts()` (`backend/app/db/opensearch.py`) — **Implemented** at the data-model level.
- Every endpoint except `GET /health` requires a valid JWT (`core/dependencies.py::get_current_user()`, SS-015) and derives `tenant_id` from the authenticated token's claim (`CurrentUser.tenant_id`), never from caller-supplied input — **Implemented, enforcement is real**:
  - Missing or invalid tokens are rejected with `401` before the route body runs.
  - A `tenant_id` supplied anywhere in a request body or query string is optional; if present it must match the token's `tenant_id` or the request is rejected with `403` (`TenantMismatchError`) — it is never used to select which tenant's data is read or written.
  - Within an ingest batch, each log's own `tenant_id` field (if any) is unconditionally overwritten with the authenticated value.
- Role-based access control (`UserRole`: `admin`/`analyst`/`viewer`) is enforced via `core/dependencies.py::require_role()` (SS-017) — e.g. manually creating or transitioning an incident requires at least `analyst`.
- Login and registration are rate-limited (SS-067) to slow down credential brute-forcing and mass account creation. See `docs/security-review.md` for the full auth security posture, including deliberately-deferred gaps (e.g. JWT refresh doesn't re-check the DB for user existence/active status).
- Not yet built: an admin-invite flow gating who can register a user against a given `tenant_id` in the first place — anyone who knows (or guesses) a `tenant_id` can currently self-register a `viewer`-role user against it.

## 5. Summary Table

| Layer | Implementation state |
|---|---|
| Source | Synthetic, Wazuh, CloudTrail, GuardDuty, CloudLens all implemented |
| Ingestion | Core pipeline + all adapters + async post-ingest processing implemented |
| Processing | Enrichment, correlation, risk scoring, NL assistant, anomaly detection, reporting, notifications all implemented |
| Storage | OpenSearch, PostgreSQL, Redis all implemented |
| API | All endpoint groups implemented; no stub routers remain |
| Presentation | React frontend implemented |
| CloudLens | Fully working standalone, integrated via the cloud findings bridge |
