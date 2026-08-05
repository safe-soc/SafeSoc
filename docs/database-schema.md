# SafeSOC — Database Schema

SafeSOC's target storage layer is three-tier (OpenSearch + PostgreSQL + Redis, per `tech-stack.md`). Only OpenSearch is implemented today.

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
| Enrichment | `ti_enriched` | `boolean` | Defaults `false` — no writer sets this to `true` yet |
| Enrichment | `ti_result.*` | nested object | Schema defined (`TIResult` in `schemas/log.py`); never populated — enrichment isn't implemented |
| Enrichment | `risk_score` | `integer` | Defaults `0`; no scoring service writes to it |
| Enrichment | `anomaly_score` | `float` | Optional; no anomaly service writes to it |

**Not implemented despite being described in the report:**
- Bulk write batching at 500 docs/request — `bulk_index_logs()` sends one bulk request per monthly-index group with no internal chunking; a single oversized batch is sent as one request to OpenSearch rather than split into 500-doc chunks. (Note: `SS-005` caps the *total* logs per ingest request at `INGEST_BATCH_SIZE`, which is a different thing from chunking a single bulk write into sub-batches.)

## 2. PostgreSQL (Planned)

`backend/app/db/postgresql.py` is an empty file. `backend/app/core/config.py` already defines connection settings (`POSTGRES_HOST/PORT/DB/USER/PASSWORD`, plus `postgres_url` / `postgres_url_sync` properties for async and sync drivers), and `backend/alembic.ini` exists at the backend root — but:

- No SQLAlchemy models exist (`backend/app/models/__init__.py` is empty).
- No Alembic migration has ever been generated (`backend/migrations/versions/` contains only `.gitkeep`).
- `asyncpg`/`sqlalchemy`/`alembic` are **not** in `backend/requirements.txt` yet, so the app can't currently connect even if code were added.

Per the SRS (§3.3, §3.5), PostgreSQL is intended to hold: tenants, users, incidents, threat-intel cache. None of these tables are defined anywhere in the repo — table design is a Phase 2 task, not merely an implementation gap.

## 3. Redis (Planned)

`backend/app/db/redis.py` is an empty file. `redis_url` is already computed in `core/config.py`. Per the SRS, Redis is intended for: attack-chain correlation sliding windows (1-hour TTL, `CORRELATION_WINDOW_TTL` already defined in config), task queues, and session data. None of this exists yet, and `redis` is not in `backend/requirements.txt`.

## 4. Summary

| Store | Purpose (per SRS) | Status |
|---|---|---|
| OpenSearch | Log/alert storage & search | Implemented |
| PostgreSQL | Tenants, users, incidents, TI cache | Planned — no models, no migrations, no driver dependency |
| Redis | Correlation windows, queues, sessions | Planned — no client, no dependency |
