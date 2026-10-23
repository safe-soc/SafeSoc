# SafeSOC — Requirements Status

Source: Software Requirements Specification, Phase 1 Report (Chapter 3). Every requirement below is tagged against the current state of this repository.

Status legend: **Implemented** · **Partial** (some part works, rest missing) · **Planned** (spec'd, no code yet).

## 1. Product Perspective

SafeSOC is intended to sit between expensive enterprise SIEMs and unmanaged open-source tools (Wazuh/ELK), providing an operations layer — enrichment, correlation, investigation, reporting — on top of open-source detection. **Implemented.** The full operations layer (enrichment, correlation, NL investigation, risk scoring, reporting) is built on top of the ingestion/normalization foundation, per §3 below.

## 2. User Classes & Access Control

| User class | Status |
|---|---|
| SMB IT Administrator, Business Owner, Security Consultant, Platform Administrator (defined roles) | **Implemented** — JWT-based user model (`User`, `Tenant` models), registration/login/refresh (SS-012–014). |
| Role-based access (Admin / Analyst / Viewer) | **Implemented** — `UserRole` enum (`core/enums.py`) enforced via `core/dependencies.py::require_role()` (SS-017); e.g. incident creation/transitions require at least `analyst`. |

## 3. Core Functional Requirements

| Requirement | Status | Evidence |
|---|---|---|
| **Log ingestion & normalization** — REST endpoint, single + batch (up to 1,000/request), universal `NormalizedLog` schema, per-batch partial failure handling, UUID `alert_id` + dual timestamps | **Implemented** | `routers/v1/ingest.py`, `schemas/log.py`, `services/ingestion.py`. Batch cap is enforced (SS-005) at `settings.INGEST_BATCH_SIZE` — 500 by default, not the report's stated 1,000; the cap is config-driven rather than hardcoded to the SRS figure. JWT-required since SS-016. |
| Source-specific adapters (Wazuh, CloudTrail, GuardDuty, CloudLens, synthetic) | **Implemented** | `adapters/{wazuh,cloudtrail,guardduty,cloudlens}.py` each parse and transform that source's native payload; `services/ingestion.py::ADAPTER_REGISTRY` dispatches by `source` field (SS-018–021, SS-038). |
| Monthly OpenSearch index partitioning | **Implemented** | `db/opensearch.py` (`_build_index_name`), mapping in `db/mappings/alert_mapping.py`. |
| Index Lifecycle Management (auto-delete after 90 days) | **Implemented** | `db/opensearch.py` (`ensure_ilm_policy`), policy defined in `db/mappings/ilm_policy.py`, applied idempotently on backend startup (SS-006). Retention period is `settings.OPENSEARCH_ILM_RETENTION_DAYS` (90 by default). Applies to new indices via an `ism_template`; pre-existing indices aren't retroactively affected. |
| **Threat intelligence enrichment** (AbuseIPDB, VirusTotal, PostgreSQL cache, rate limiting, async) | **Implemented** | `clients/{abuseipdb,virustotal}.py`, `services/enrichment.py`, `models/ti_cache.py` (SS-022–025). Runs asynchronously post-ingest via `tasks/enrichment.py` so TI latency never delays the ingestion response (SS-026). |
| **Natural language investigation assistant** (8 intents + a tenant-wide overview, MCP orchestration, conversation context) | **Implemented** | `services/investigation.py` (intent classification, SS-044), `mcp/tools.py` (SS-045), Redis-backed session context (SS-046), `POST /api/v1/investigate` (SS-047). LLM via `clients/{ollama,groq}.py` (SS-042–043). |
| **Attack chain correlation engine** (6 patterns, Redis sliding windows, MITRE mapping) | **Implemented** | `services/correlation.py` (6 detectors, SS-028), Redis sliding windows (SS-027), `workers/correlation_worker.py` (SS-030), MITRE ATT&CK mapping (SS-029), auto-creates/merges incidents on detection (SS-031). |
| **Endpoint risk scoring** (0–100, decay, four risk levels) | **Implemented** | `services/risk_scoring.py` (SS-032), scheduled re-scoring via `tasks/scoring.py` (SS-033), exposed via `GET /api/v1/endpoints` (SS-034). |
| **Incident management** (lifecycle, linked alerts, notes, reports) | **Implemented** | `routers/v1/incidents.py`: manual creation, list, get, lifecycle transitions (`open` → `investigating` → `resolved`/`false_positive`, invalid transitions rejected with 409), alert linking, and investigation notes (SS-036–037), all JWT/role-gated. |
| **Cloud security monitoring** (CloudTrail/GuardDuty ingestion, unified queue) | **Implemented** | CloudTrail/GuardDuty via adapters above; CloudLens findings bridged via `POST /api/v1/cloud/findings` into the same unified ingestion pipeline (SS-038–040) — see `architecture.md` §3. |
| **Anomaly detection** (Isolation Forest, Z-score) | **Implemented** | `services/anomaly.py` (7-feature vector scored against a trained Isolation Forest, SS-050), Z-score network-volume-spike detection (SS-051). Training pipeline: `ml/generate_training_data.py` (SS-048), `ml/train.py` (SS-049), trained model at `ml/model/isolation_forest.pkl`. |
| **Automated reporting** (weekly PDF digest via WeasyPrint) | **Implemented** | `services/reporting.py` (SS-052), scheduled via `tasks/reporting.py` (SS-053), listed/downloaded via `GET /api/v1/reports` (SS-054). WeasyPrint is in `backend/requirements.txt`. |
| **Multi-tenant architecture** (query-layer isolation, JWT, bcrypt, 3 roles) | **Implemented** | `tenant_id` is a required, filtered field in ingestion and search (data-model level isolation), derived from a verified JWT (SS-016) rather than caller-supplied. bcrypt password hashing (SS-012), role enforcement (SS-017). Login/register are rate-limited (SS-067) — see `security-review.md`. |
| **Synthetic data generation** (multiple attack scenarios, demo mode) | **Implemented** | `injector/injector.py` has 6 named attack scenarios, one per correlation pattern (SS-064); `injector/demo.py` is a one-command comprehensive demo mode with an active and a resolved incident (SS-065). |

## 4. Non-Functional Requirements

| Requirement | Status | Notes |
|---|---|---|
| ≥100 log events/sec ingestion | **Implemented, verified** | `backend/tests/perf/benchmark.py` (SS-066): 582.3 and 452.8 events/sec measured across two runs (Docker Compose, dev setup) — see `testing.md` §5 for full results. |
| Alert queries < 500ms | **Implemented, verified** | Same benchmark: p95 158.7ms and 130.7ms across two runs, well under target — see `testing.md` §5. |
| NL assistant responds within 15s | **Implemented** | `POST /api/v1/investigate` bounds LLM answer generation via `INVESTIGATION_LLM_TIMEOUT_SECONDS` (default 10s), leaving headroom under the 15s target for the (normally sub-second) classification + tool-query steps that happen first; falls back to a templated summary if the LLM is slow/unreachable. See `docs/api-design.md`'s `/api/v1/investigate` section. |
| Docker services restart automatically on failure | **Implemented** | `docker-compose.yml` sets `restart: unless-stopped` on all services (see `deployment.md`). |
| Single-command startup (`docker compose up`) | **Implemented** | `docker compose up --build` from repo root; OpenSearch, Postgres, and Redis reach healthy before the backend/worker/beat services start. |
| Cross-platform (Ubuntu/macOS/Windows + Docker) | **Partially verified** | Verified working on Windows + Docker Desktop. Not yet tested on Ubuntu/macOS. |
| No vendor-specific cloud services required | **Implemented** (by design) | Stack is OpenSearch/Postgres/Redis/FastAPI/Docker; no cloud-managed services are referenced in code (the LLM providers are the one external dependency, and Ollama runs fully local). |
| Graceful handling of external API failures (cached fallback) | **Implemented** | `services/enrichment.py` falls back to a stale `ti_cache` entry (or a no-op) if a TI provider call fails, rather than propagating the error. `clients/telegram.py::send_message()` similarly no-ops rather than raising when unconfigured; raises a typed `TelegramError` (not left to propagate as a raw `requests` exception) on a genuine send failure. |

## 5. Technology Stack Requirements

See `tech-stack.md` for the full comparison between the report's target stack and what's actually declared in `backend/requirements.txt`.

## 6. Summary

Of the ~13 core functional requirements in the SRS, **all are now implemented**, closing out the Phase 2 backlog described in `docs/roadmap-issues.md` (SS-001 through SS-067). The Phase 1 report's own scope statement (§5.1) — Phase 1 targeting the core data pipeline plus the standalone CloudLens module, deferring the intelligence and user-facing layers to Phase 2 — has now been fully realized; see `docs/project-roadmap.md` and `PRODUCT_ROADMAP.md` for what (if anything) remains beyond this backlog.
