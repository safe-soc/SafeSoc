# SafeSOC — Database Schema

SafeSOC's storage layer is three-tier (OpenSearch + PostgreSQL + Redis, per `tech-stack.md`). All three are implemented.

## 1. OpenSearch — `safesoc-alerts-{YYYY}.{MM}` (Implemented)

Index pattern: one index per calendar month, e.g. `safesoc-alerts-2026.05`. Created automatically on first write to a new month (`ensure_index_exists()` in `backend/app/db/opensearch.py`). Mapping source: `backend/app/db/mappings/alert_mapping.py`. Settings: 1 shard, 0 replicas, 5s refresh interval (single-node dev configuration — not tuned for production replica/shard counts).

**Retention (ISM policy, SS-006):** an Index State Management policy (`safesoc-alerts-retention-policy`, defined in `backend/app/db/mappings/ilm_policy.py`) is created idempotently on backend startup (`ensure_ilm_policy()` in `db/opensearch.py`) if it doesn't already exist. It targets any index matching `safesoc-alerts-*` via an `ism_template` — new indices pick up the policy automatically at creation time — and deletes them once they exceed `settings.OPENSEARCH_ILM_RETENTION_DAYS` (90 by default). Indices created before this policy existed are not retroactively affected.

The mapping mirrors the `NormalizedLog` Pydantic schema (`backend/app/schemas/log.py`) field-for-field:

| Category | Field | OpenSearch type | Notes |
|---|---|---|---|
| Identity | `alert_id` | `keyword` | UUID4, generated server-side if not supplied |
| Identity | `tenant_id` | `keyword` | Required; used as the mandatory query filter |
| Source | `source` | `keyword` | `wazuh` \| `synthetic` \| `aws_cloudtrail` \| `aws_guardduty` |
| Source | `log_type` | `keyword` | `authentication` \| `network` \| `process` \| `file` \| `privilege` \| `cloud` \| `system` |
| Timing | `timestamp` | `date` | Original event time (required) |
| Timing | `ingested_at` | `date` | Set server-side at ingestion |
| Host Context | `host_id` | `keyword` | Required |
| Host Context | `host_ip` | `ip` | Required |
| Host Context | `host_os` | `keyword` | Optional |
| Event Context | `user` | `keyword` | Defaults to `"unknown"` |
| Event Context | `action` | `keyword` | Required |
| Event Context | `description` | `text` | Required, full-text searchable |
| Event Context | `severity` | `keyword` | `low` \| `medium` \| `high` \| `critical` |
| Detection | `rule_id` | `keyword` | Optional |
| Detection | `mitre_technique` | `keyword` | Optional |
| Detection | `mitre_tactic` | `keyword` | Optional |
| Network | `source_ip`, `destination_ip` | `ip` | Optional |
| Network | `source_port`, `destination_port` | `integer` | Optional |
| Network | `protocol` | `keyword` | Optional |
| File | `file_path`, `file_hash` | `keyword` | Optional |
| File | `file_size` | `long` | Optional |
| Process | `process_name`, `parent_process` | `keyword` | Optional |
| Process | `process_id` | `integer` | Optional |
| Process | `command_line` | `text` | Optional |
| Raw | `raw_log` | `text`, `index: false` | Stored but not searchable; default `"{}"` |
| Enrichment | `ti_enriched` | `boolean` | Defaults `false`, set `true` by `services/enrichment.py` once a TI lookup completes (SS-025) |
| Enrichment | `ti_result.*` | nested object | Schema defined (`TIResult` in `schemas/log.py`); populated by `services/enrichment.py` (SS-025) |
| Enrichment | `risk_score` | `integer` | Defaults `0`; written by `services/risk_scoring.py` / `tasks/scoring.py` (SS-032–033) |
| Enrichment | `anomaly_score` | `float` | Optional; written by `services/anomaly.py` (SS-050) |

**Not implemented despite being described in the report:**
- Bulk write batching at 500 docs/request — `bulk_index_logs()` sends one bulk request per monthly-index group with no internal chunking; a single oversized batch is sent as one request to OpenSearch rather than split into 500-doc chunks. (Note: `SS-005` caps the *total* logs per ingest request at `INGEST_BATCH_SIZE`, which is a different thing from chunking a single bulk write into sub-batches.)

## 2. PostgreSQL (Implemented)

`backend/app/db/postgresql.py` provides an async engine/session factory (`async_session_factory`, `get_db()` FastAPI dependency) built from `settings.postgres_url` (SS-007). Alembic migrations live under `backend/migrations/versions/`. `sqlalchemy[asyncio]`, `asyncpg`, and `alembic` are all in `backend/requirements.txt`.

| Table | Model | Purpose |
|---|---|---|
| `tenants` | `models/tenant.py::Tenant` | Root of multi-tenant isolation: `id` (UUID PK), `name`, `created_at`. |
| `users` | `models/user.py::User` | Login identity scoped to a tenant: `id`, `tenant_id` (FK), `email`, `password_hash` (bcrypt), `role` (`user_role` enum: admin/analyst/viewer), `created_at`. Unique on `(tenant_id, email)`. |
| `incidents` | `models/incident.py::Incident` | `id`, `tenant_id` (FK), `status` (`incident_status` enum: open/investigating/resolved/false_positive), `alert_ids` (JSON list), `assigned_analyst_id` (FK, nullable), `created_at`/`updated_at`. |
| `incident_state_transitions` | `models/incident.py::IncidentStateTransition` | Append-only audit log: one row per status change (including creation, `from_status=NULL` → `OPEN`), with the acting user and timestamp. Never updated or deleted. |
| `incident_notes` | `models/incident.py::IncidentNote` | Append-only analyst notes attached to an incident: `incident_id` (FK), `author_user_id` (FK), `body`, `created_at`. |
| `ti_cache` | `models/ti_cache.py::TICache` | Cache-before-call TTL cache for TI provider lookups: `indicator`, `provider` (`ti_provider` enum), `result` (JSON), `is_malicious`, `expires_at`. Unique on `(indicator, provider)`. Expiry computed via `compute_expiry()`: 7-day TTL for malicious indicators, 24h for clean (`TI_CACHE_MALICIOUS_TTL`/`TI_CACHE_CLEAN_TTL`). |
| `endpoints` | `models/endpoint.py::Endpoint` | A known host's most recently computed risk score/level: `tenant_id` (FK), `host_id`, `risk_score`, `risk_level` (`risk_level` enum), `updated_at`. Unique on `(tenant_id, host_id)`. Upserted by the periodic risk-recalculation task (SS-033), not created by ingestion directly. |

## 3. Redis (Implemented)

`backend/app/db/redis.py::get_client()` returns an async client built from `settings.redis_url` (SS-010). `redis` is in `backend/requirements.txt`. Used for:

- **Attack-chain correlation sliding windows** (SS-027): sorted sets keyed `correlation:window:{tenant_id}:{host_id}`, one member per event, TTL refreshed to `CORRELATION_WINDOW_TTL` (1 hour default) on every write.
- **Investigation conversation/session context** (SS-046): a namespaced key per `(tenant_id, session_id)`, TTL refreshed on every write (`INVESTIGATION_SESSION_TTL_SECONDS`, 10 minutes default).
- **Real-time event pub/sub** (SS-063): a per-tenant channel that `routers/ws.py` subscribes to, publishing new-alert/chain-detected events pushed by the ingestion and correlation paths.
- **Auth rate-limit counters** (SS-067): fixed-window counters (`ratelimit:login:{tenant_id}:{email}`, `ratelimit:register:{client_ip}`), TTL set on the first increment of each window.
- **Celery broker + result backend** (SS-011): task queuing for enrichment, correlation, scoring, reporting, and notification workers.

## 4. Summary

| Store | Purpose (per SRS) | Status |
|---|---|---|
| OpenSearch | Log/alert storage & search | Implemented |
| PostgreSQL | Tenants, users, incidents, TI cache, endpoints | Implemented |
| Redis | Correlation windows, sessions, pub/sub, rate limits, Celery broker | Implemented |
