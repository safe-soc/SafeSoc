# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning follows the pre-1.0 scheme described in `PRODUCT_ROADMAP.md`: breaking changes are expected between `v0.x.0` releases, each representing a release-worthy chunk of the Phase 2 backlog (`docs/roadmap-issues.md`) landing.

## [Unreleased]

## [v0.4.0-alpha] - 2026-08-06

Closes out Milestone 5 (Threat Intelligence Enrichment), `docs/roadmap-issues.md` SS-022 through SS-026 — per `PRODUCT_ROADMAP.md`'s release mapping, this is the `v0.4.0` chunk of the Phase 2 backlog. This release also carries the accumulated Milestone 2–4 work (SS-007–021: PostgreSQL/Redis/Celery, JWT auth and tenant isolation, and the Wazuh/CloudTrail/GuardDuty ingestion adapters) that landed on `main` across prior sessions without an intermediate tag; see git history for that detail; this entry itemizes Milestone 5 specifically.

### Added

- VirusTotal and AbuseIPDB clients (`app/clients/virustotal.py`, `app/clients/abuseipdb.py`): IP/file-hash reputation lookups normalized into the shared `TIResult` shape, each with its own client-side rate limiting (VT: sliding 60s window, blocks; AbuseIPDB: sliding 24h window, raises once exhausted) and a typed exception on network/HTTP failure instead of a raw `requests` error. (SS-022, SS-023)
- `ti_cache` Postgres table (`app/models/ti_cache.py`): caches TI lookups by `(indicator, provider)`, with `compute_expiry()` reading `TI_CACHE_MALICIOUS_TTL`/`TI_CACHE_CLEAN_TTL` from config (7-day/24-hour defaults) rather than a hardcoded interval. (SS-024)
- Enrichment service (`app/services/enrichment.py`): given a log's IP or file-hash indicator, checks `ti_cache` before calling a provider, merges VirusTotal + AbuseIPDB results for IPs, writes back to the cache and to the OpenSearch document's `ti_result`/`ti_enriched`/`risk_score` fields (new `db/opensearch.py::update_alert_ti_fields`), and never lets a provider outage raise past the service boundary — falls back to a stale cache entry, or a no-op, per SRS §3.4. (SS-025)
- Enrichment now runs asynchronously: `POST /api/v1/ingest` queues `app/tasks/enrichment.py::enrich_alert` (Celery) for every accepted log via FastAPI `BackgroundTasks`, so TI latency never delays the ingestion response — measured live at 69ms response time against a 1.13s background enrichment run. `docs/decisions.md` ADR-005 updated from "implemented by omission" to real async deferral. (SS-026)

### Fixed

- Celery worker (`app/tasks/celery_app.py`) never imported the enrichment task module, so `enrich_alert` was registered on the producer (backend) side but completely unknown to the worker — discovered via live Docker verification, fixed via `include=["app.tasks.enrichment"]`. Also added short broker connection timeouts and disabled connection retry, since a hung (not merely refused) broker connection would silently defeat the whole point of deferring enrichment asynchronously.
- `docker-compose.yml`'s `worker` service was missing `OPENSEARCH_HOST`/`POSTGRES_HOST` entirely (it only ever needed `REDIS_HOST` for SS-011's trivial `ping` task) — with real enrichment work, the worker now needs both, and was silently trying to reach `localhost` instead of the `opensearch`/`postgres` containers.

## [v0.1.0-alpha] - 2026-08-05

First Phase 2 release: closes out Milestone 1 (Deployment Foundation & Test Bootstrap), `docs/roadmap-issues.md` SS-001 through SS-006.

### Added

- Root `docker-compose.yml` orchestrating `opensearch` and `backend` services. The backend waits for OpenSearch's healthcheck before starting; host ports are overridable via `OPENSEARCH_PORT`/`BACKEND_PORT` env vars. (SS-001)
- Automated backend test suite: 40 tests (`pytest` + `pytest-asyncio` + `httpx`) covering `NormalizedLog` validation, ingestion partial-failure handling, OpenSearch index naming and connectivity checks, the exception handler, and the ingestion batch cap — plus reusable fixtures in `backend/tests/conftest.py`. Runs fully offline, no live OpenSearch required. (SS-002)
- `pytest` wired into CI: the `safesoc-backend` job in `.github/workflows/ci.yml` now runs the test suite on every push/PR, in addition to the existing install and import-check steps. (SS-003)
- Ingestion batch-size cap: `POST /api/v1/ingest` rejects batches larger than `settings.INGEST_BATCH_SIZE` (500 by default) with a `422`, before any log in the batch is processed or written. (SS-005)
- OpenSearch Index State Management (ISM) retention policy: `safesoc-alerts-*` indices are automatically deleted once they exceed `settings.OPENSEARCH_ILM_RETENTION_DAYS` (90 by default). Applied idempotently on backend startup and picked up automatically by new indices via an `ism_template`. (SS-006)

### Fixed

- `SafeSOCError` exception handler (previously defined but never registered) is now wired up in `main.py`, and `POST /api/v1/ingest`'s validation errors raise the typed `IngestionError` instead of ad-hoc `HTTPException`s. This changes the JSON body of those specific error responses from FastAPI's default `{"detail": ...}` to the consistent `{"error": ..., "status_code": ...}` shape. (SS-004)
