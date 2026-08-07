# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning follows the pre-1.0 scheme described in `PRODUCT_ROADMAP.md`: breaking changes are expected between `v0.x.0` releases, each representing a release-worthy chunk of the Phase 2 backlog (`docs/roadmap-issues.md`) landing.

## [Unreleased]

## [v0.12.0-alpha] - 2026-08-07

Closes Milestone 14 (Non-Functional Hardening & QA), SS-066–067, plus two bug reports (BUG-001, BUG-002) found during live verification of this milestone. SS-068 (this documentation-sync pass) is tracked separately since it's meant to recur, not close out once. Not the `v1.0.0` PRODUCT_ROADMAP.md describes — SS-071 (audit log) and SS-072 (installer script) are still outstanding.

### Added

- Load/performance benchmark harness (`backend/tests/perf/benchmark.py`): measures ingestion throughput (SRS target ≥100 events/sec) and alert-query p95 latency (<500ms) against a real running backend; not part of the CI `pytest` run (no live stack in CI) — its pure aggregation/percentile math is covered separately (`test_benchmark.py`). Measured live at 452–582 events/sec and 130–159ms p95, both well over target. (SS-066)
- Security hardening pass, documented in full in `docs/security-review.md` (SS-067): a Redis-backed fixed-window rate limiter on `/api/v1/auth/login` (5/5min per tenant+email) and `/register` (10/5min per IP) (`services/rate_limit.py`); a startup guard refusing to boot in `ENV=production` with the default `JWT_SECRET` still set; a constant-time (`hmac.compare_digest`) comparison for the CloudLens service token, replacing a timing-unsafe `!=`; an 8-character minimum on registration passwords.

### Fixed

- **BUG-001**: `injector/injector.py`'s standalone CLI never authenticated before sending logs (only `demo.py` did), so `python injector.py --scenario brute_force` 401'd against the JWT-required ingest endpoint. `injector.py` now logs in first, defaulting to the same demo tenant `demo.py` provisions; `--tenant-id`/`--email`/`--password` target a different user, `--no-auth` restores the pre-auth unauthenticated payload shape.
- **BUG-002**: `injector/demo.py` misreported a valid correlation-engine merge as a timeout ("no incident detected within the timeout"). Root cause (confirmed live, not guessed): the demo tenant's in-progress incident is deliberately left open across runs, so re-running `demo.py` correctly *merges* the re-detected chain into that still-open incident (SS-031) rather than minting a new one — but the wait logic was checking for an unseen incident ID, so a correct merge looked like nothing happened. Fixed by waiting for an incident whose `alert_ids` overlaps with what was just sent, which is correct whether the result is a merge or a fresh incident. Verified live: 6 consecutive runs against the same heavily-reused demo tenant, zero timeouts. Telegram non-delivery (the bug report's other symptom) was confirmed to be unconfigured `TELEGRAM_BOT_TOKEN`/`TELEGRAM_CHAT_ID` — the code's no-op-when-unconfigured behavior is correct by design, not a defect; delivery was verified live once real credentials were supplied.

## [v0.11.0-alpha] - 2026-08-07

Closes Milestone 13 (Synthetic Data & Demo Mode), SS-064–065.

### Added

- Six named attack scenarios in `injector/injector.py` (`brute_force`, `successful_compromise`, `recon_to_exploitation`, `privilege_escalation`, `data_exfiltration`, `lateral_movement`), one per correlation pattern (SS-028), engineered to satisfy that detector's own threshold constants. (SS-064)
- `injector/demo.py`: one command (`python injector/demo.py`) provisions a demo tenant, a realistic 150-event alert history spread across 14 days, an in-progress (left-open) incident, and a resolved incident — idempotent, safe to re-run. (SS-065)

## [v0.10.0-alpha] - 2026-08-07

Closes Milestone 12 (SafeSOC Frontend), SS-057–063.

### Added

- React 18 + TypeScript + Vite + Tailwind frontend scaffold (`frontend/`), matching CloudLens's stack: routing, a shared axios API client, auth context. (SS-057)
- Login flow: `ProtectedRoute` gating authenticated pages behind a valid session. (SS-058)
- Alert queue view (`Alerts.tsx`): paginated table exposing every backend filter (severity, log_type, source, host, timerange_hours). (SS-059)
- Endpoint risk dashboard (`Endpoints.tsx`), sorted by risk score descending. (SS-060)
- Incident management UI (`Incidents.tsx` list + `IncidentDetail.tsx` view/transition/link-alerts/notes). (SS-061)
- Investigation chat UI (`Investigate.tsx`), carrying `session_id` across requests so follow-up questions resolve conversation context. (SS-062)
- Real-time dashboard updates: `GET /ws?token=<JWT>` (`backend/app/routers/ws.py`) pushes new-alert/chain-detected events over a Redis pub/sub channel to the connected tenant's frontend. (SS-063)

## [v0.9.0-alpha] - 2026-08-07

Closes Milestone 11 (Automated Reporting & Notifications), SS-052–056.

### Added

- PDF report generation (`services/reporting.py`): gathers a tenant's alerts, incidents, top-risk endpoints, and cloud posture into a weekly digest via WeasyPrint. (SS-052)
- Weekly report scheduling: a Celery beat task (`tasks/reporting.py`) generating one report per known tenant on a configurable crontab (`REPORT_SCHEDULE_DAY`/`HOUR`). (SS-053)
- `GET /api/v1/reports` (list) and `GET /api/v1/reports/{filename}` (download). (SS-054)
- SafeSOC's own Telegram client (`clients/telegram.py`) — independent of CloudLens's own notifier, skips sending silently (not an error) when unconfigured. (SS-055)
- Notification service + worker (`services/notifications.py`, `workers/notification_worker.py`): a Celery task queued for every accepted critical-severity alert, plus a direct call on every detected attack chain. (SS-056)

## [v0.8.0-alpha] - 2026-08-07

Closes Milestone 10 (Anomaly Detection), SS-048–051.

### Added

- Synthetic normal-behavior training data generator (`ml/generate_training_data.py`): ~30 days of normal events with realistic diurnal/weekly volume patterns. (SS-048)
- Isolation Forest training pipeline (`ml/train.py`): aggregates the SS-048 dataset into hourly per-host feature vectors, fits and saves the model to `settings.ANOMALY_MODEL_PATH`. (SS-049)
- Anomaly scoring service (`services/anomaly.py`): extracts a 7-feature vector (login patterns, connection diversity, process frequency, temporal features) from a host's correlation-engine sliding window and scores it against the trained model. (SS-050)
- Z-score network-volume-spike detection: compares a host's recent outbound-connection rate against a longer preceding baseline. (SS-051)

## [v0.7.0-alpha] - 2026-08-07

Closes Milestone 9 (Natural Language Investigation Assistant), SS-042–047.

### Added

- Ollama client (`clients/ollama.py`) and Groq client (`clients/groq.py`), both `generate(prompt) -> str`, same interface either way. (SS-042, SS-043)
- Intent classification (`services/investigation.py::classify_intent`), 8 SRS-defined intents plus an `UNKNOWN` fallback. (SS-044)
- MCP tool definitions (`mcp/tools.py`): one typed `MCPTool` per intent, each wrapping an existing service (alert search, risk scoring, incidents, ...). (SS-045)
- Redis-backed conversation/session context (mirroring the SS-027 sliding-window pattern): a namespaced key per (tenant, session), TTL refreshed on every write. (SS-046)
- `POST /api/v1/investigate`: the orchestration point tying classification, MCP tool calls, and LLM answer generation together, bounded to meet the SRS's 15-second response target. (SS-047)

## [v0.6.0-alpha] - 2026-08-06/07

Closes Milestone 7 (Endpoint Risk Scoring & Incident Management, SS-032–037) and Milestone 8 (CloudLens Integration, SS-038–041).

### Added

- Risk scoring service (`services/risk_scoring.py::calculate_risk_score`) and a scheduled Celery beat task (`tasks/scoring.py`) re-scoring every known endpoint so time-decay behavior manifests between ingestion events. (SS-032, SS-033)
- `GET /api/v1/endpoints`: known hosts with current risk score/level, sorted descending. (SS-034)
- `Incident` model (pulled forward from Milestone 7 to unblock SS-031) and full CRUD + lifecycle endpoints (`POST`/`GET /api/v1/incidents`, transitions) — manual creation is analyst-role-gated. (SS-035, SS-036)
- Alert linking (`POST /api/v1/incidents/{id}/alerts`) and investigation notes on incidents. (SS-037)
- CloudLens `Finding` → `NormalizedLog` adapter (`adapters/cloudlens.py`), a push-based sync bridge (CloudLens calls SafeSOC after a scan completes), and `POST /api/v1/cloud/findings`/`GET /api/v1/cloud/summary` — service-token authenticated, reusing the same ingestion pipeline as every other source. (SS-038, SS-039, SS-040)
- ADR-009 documenting the decision to harmonize CloudLens's own risk score with SafeSOC's risk scoring rather than unify them into one calculation. (SS-041)

## [v0.5.0-alpha] - 2026-08-06

Closes Milestone 6 (Attack Chain Correlation Engine), SS-027–031.

### Added

- Redis sliding-window primitives (`services/correlation.py::add_event`/`get_events`): per-tenant, per-endpoint event storage in sorted sets. (SS-027)
- Six attack-chain pattern detectors evaluating a host's sliding window against a rule (credential brute force, successful compromise, recon-to-exploitation, privilege escalation, data exfiltration, lateral movement). (SS-028)
- MITRE ATT&CK technique/tactic mapping (`CorrelationPattern` enum + mapping table) for each pattern. (SS-029)
- Correlation worker (`workers/correlation_worker.py::evaluate_correlation`): a Celery task re-evaluating a host's window after every ingested alert. (SS-030)
- Auto-creates (or merges into an existing active) incident on chain detection, deduplicating re-detections of the same evolving attack rather than creating a new incident each time. (SS-031)

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
