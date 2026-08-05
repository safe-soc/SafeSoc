# SafeSOC — Phase 2 Implementation Roadmap & Issue Backlog

This document breaks every remaining (non-implemented or partially-implemented) feature into fileable GitHub Issues, grouped into milestones representing development sprints. It is built from the current state of the code and `docs/` — **not** the Phase 1 report in isolation — so it reflects what's actually in the repository today, including work completed in later documentation sessions (e.g. `.env.example`, `.github/workflows/ci.yml`, `README.md`, and `CLAUDE.md` are now populated; a root `docker-compose.yml` is still missing).

There is no GitHub remote configured on this repository yet (`git remote -v` is empty), so nothing here has been filed automatically. Each entry below is written to be copy-pasted into `gh issue create` (or the GitHub UI) once a remote exists.

## How to read this document

- **Priority:** Critical (blocks multiple other issues or a core deliverable) · High · Medium · Low
- **Effort:** person-days for one contributor, assuming a 4-person part-time student team — XS (<0.5d) · S (0.5–1d) · M (1–3d) · L (3–5d) · XL (>5d, should be split further before starting)
- **Dependencies:** other issue IDs that must land first
- **Files likely to change:** best-guess based on current repo layout; the implementer may need more

IDs are sequential across the whole backlog (`SS-001`...) so they can be referenced as dependencies regardless of milestone.

---

## Milestone Summary

| # | Milestone (Sprint) | Goal | Issues | Est. Effort |
|---|---|---|---|---|
| 1 | Deployment Foundation & Test Bootstrap | Make the repo runnable in one command and testable | SS-001–006 | ~10.5d |
| 2 | Storage Tier — PostgreSQL, Redis, Celery | Stand up the two missing databases + task queue | SS-007–011 | ~9d |
| 3 | Authentication & Multi-Tenancy Enforcement | Make `tenant_id` trustworthy | SS-012–017 | ~11d |
| 4 | Source Adapters & Ingestion Hardening | Accept real Wazuh/AWS logs, not just synthetic | SS-018–021 | ~7d |
| 5 | Threat Intelligence Enrichment | Auto-enrich alerts with VT/AbuseIPDB | SS-022–026 | ~9d |
| 6 | Attack Chain Correlation Engine | Detect multi-step attacks in real time | SS-027–031 | ~12d |
| 7 | Endpoint Risk Scoring & Incident Management | Turn alerts into prioritized, trackable work | SS-032–037 | ~13d |
| 8 | CloudLens Integration | Merge cloud findings into the unified alert queue | SS-038–041 | ~9d |
| 9 | Natural Language Investigation Assistant | Plain-English querying via MCP + LLM | SS-042–047 | ~15d |
| 10 | Anomaly Detection | Isolation Forest + Z-score scoring | SS-048–051 | ~8d |
| 11 | Automated Reporting & Notifications | Weekly PDF digests + Telegram alerts | SS-052–056 | ~9d |
| 12 | SafeSOC Frontend | React dashboard for all of the above | SS-057–063 | ~22d |
| 13 | Synthetic Data & Demo Mode | Realistic attack scenarios for testing/demo | SS-064–065 | ~4d |
| 14 | Non-Functional Hardening & QA | Perf, security, docs sync | SS-066–068 | ~7d |

**Total: 68 issues, ~145 person-days.** For a 4-person part-time student team this is roughly the scope of a full second semester — treat the milestone order as the recommended build sequence, not a commitment to build everything.

---

## Milestone 1 — Deployment Foundation & Test Bootstrap

**Why first:** every other milestone assumes the backend is easy to run locally and has a place to put tests. Nothing here depends on Phase 2 features, so it can start immediately and in parallel.

#### SS-001 — Add root `docker-compose.yml` for backend + OpenSearch
**Status:** ✅ Done (2026-08-05)
**Description:** Create a `docker-compose.yml` at the repository root that runs `opensearch` (single-node, security plugin disabled) and `backend` (building `backend/Dockerfile`) together, with a health check gating backend startup on OpenSearch readiness, matching what `docs/deployment.md` and the Phase 1 report describe but which doesn't exist yet.
**Priority:** Critical · **Effort:** M · **Dependencies:** none
**Acceptance Criteria:**
- [x] `docker compose up` from repo root starts both services with no manual steps beyond `.env` values
- [x] `backend` container waits for `opensearch` healthcheck before starting (matches report §4.5)
- [x] `GET /health` returns `"opensearch": "connected"` within a reasonable startup window
- [x] `docs/deployment.md` updated to remove the "missing" callout for this file
**Files changed:**
- `docker-compose.yml` (new)
- `docs/deployment.md`, `docs/decisions.md`, `docs/project-roadmap.md`, `docs/requirements.md`, `docs/tech-stack.md`, `CLAUDE.md`, `README.md` (doc accuracy sync)

#### SS-002 — Bootstrap backend automated test suite
**Status:** ✅ Done (2026-08-05)
**Description:** Add `pytest`, `pytest-asyncio`, and `httpx` to `backend/requirements.txt`, populate `backend/tests/conftest.py` with reusable fixtures (test client, mocked/ephemeral OpenSearch), and write the first real tests for the code that already exists.
**Priority:** Critical · **Effort:** M · **Dependencies:** none
**Acceptance Criteria:**
- [x] `pytest` runs from `backend/` and collects >0 tests (31 collected)
- [x] Coverage includes: `NormalizedLog` validation (valid + missing-required-field cases), `process_ingest_batch` partial-failure behavior, `_build_index_name` month/year boundaries, `/health` degraded-state behavior
- [x] `conftest.py` no longer empty; fixtures documented with a one-line docstring each
**Files changed:**
- `backend/requirements.txt`
- `backend/tests/conftest.py`
- `backend/tests/test_ingestion.py` (new)
- `backend/tests/test_schemas.py` (new)
- `backend/tests/test_opensearch.py` (new)
- `docs/testing.md` (doc accuracy sync)

#### SS-003 — Wire pytest into CI
**Status:** ✅ Done (2026-08-05)
**Description:** Add a `pytest` step to the existing `safesoc-backend` job in `.github/workflows/ci.yml` (currently only an import smoke test), now that real tests exist.
**Priority:** High · **Effort:** XS · **Dependencies:** SS-002
**Acceptance Criteria:**
- [x] CI fails if any backend test fails (added `- name: Run tests / run: pytest` step, after install and import check)
- [x] `docs/testing.md` updated to reflect that a real suite now runs in CI
**Files changed:**
- `.github/workflows/ci.yml`
- `docs/testing.md`

#### SS-004 — Register the `SafeSOCError` exception handler
**Status:** ✅ Done (2026-08-05)
**Description:** `backend/app/core/exceptions.py` defines `SafeSOCError`/`IngestionError`/`OpenSearchError` and a handler, but `main.py` never calls `app.add_exception_handler(...)`, and the ingest router raises inline `HTTPException` instead of the typed exceptions — two disconnected error-handling patterns exist today (see `docs/coding-standards.md` §8). Pick one and make it consistent.
**Priority:** Medium · **Effort:** S · **Dependencies:** none
**Acceptance Criteria:**
- [x] `SafeSOCError` handler is registered in `main.py` (`app.add_exception_handler(SafeSOCError, safesoc_exception_handler)` — registering the base class catches all subclasses)
- [x] Existing endpoints raise the typed exceptions where applicable (`ingest.py`'s two inline `HTTPException`s → `IngestionError`)
- [x] A regression test confirms the handler produces the documented `{"error": ..., "status_code": ...}` shape (`test_exceptions.py`, 4 new tests)
**Files changed:**
- `backend/app/main.py`
- `backend/app/routers/v1/ingest.py`
- `backend/tests/test_exceptions.py` (new)
- `docs/coding-standards.md`, `docs/api-design.md`, `docs/testing.md` (doc accuracy sync)

**Scoped out (not this issue):** `OpenSearchError` is registered and handler-ready but has no raise site yet — the ingestion path's OpenSearch I/O failures still surface as an unhandled 500. `core/exceptions.py`'s "Files likely to change" listing didn't call for touching `services/ingestion.py`/`db/opensearch.py`, and doing so wasn't necessary to satisfy this issue's acceptance criteria — left as a clearly-documented follow-on (see `docs/coding-standards.md` §8) rather than folded in here.

#### SS-005 — Enforce the 1,000-log ingestion batch cap
**Description:** The SRS specifies a max batch size of 1,000 logs per `/api/v1/ingest` request; `INGEST_BATCH_SIZE=500` exists in config but nothing currently rejects an oversized request.
**Priority:** Medium · **Effort:** XS · **Dependencies:** none
**Acceptance Criteria:**
- A request with more than `INGEST_BATCH_SIZE` logs returns `422` with a clear error message, none of the batch is written
- Test covers exactly-at-limit and one-over-limit
**Files likely to change:**
- `backend/app/routers/v1/ingest.py`
- `backend/tests/test_ingestion.py`

#### SS-006 — OpenSearch Index Lifecycle Management (90-day retention)
**Description:** Implement the ILM policy described in the report (§4.4) so `safesoc-alerts-*` indices older than 90 days are automatically deleted, bounding storage growth as designed.
**Priority:** Low · **Effort:** S · **Dependencies:** SS-001 (needs a running OpenSearch to apply the policy against)
**Acceptance Criteria:**
- ILM policy applied automatically on backend startup (or documented as a one-time setup script)
- Policy is idempotent — reapplying on restart doesn't error
- `docs/database-schema.md` updated to remove the "not implemented" callout
**Files likely to change:**
- `backend/app/db/opensearch.py`
- `backend/app/db/mappings/alert_mapping.py` (or a new `ilm_policy.py`)
- `docs/database-schema.md`

---

## Milestone 2 — Storage Tier: PostgreSQL, Redis, Celery

**Why now:** almost every remaining milestone (auth, TI cache, correlation windows, incidents, reporting) needs one or both of these databases. Building the plumbing once, early, avoids rework.

#### SS-007 — PostgreSQL driver, async engine, and connection module
**Description:** Add `sqlalchemy[asyncio]`, `asyncpg`, and `alembic` to `backend/requirements.txt`, and implement `backend/app/db/postgresql.py` (currently empty) with an async engine/session factory built from `settings.postgres_url`.
**Priority:** Critical · **Effort:** S · **Dependencies:** SS-001 (needs Postgres in compose)
**Acceptance Criteria:**
- `docker-compose.yml` gains a `postgres` service
- `db/postgresql.py` exposes a session dependency usable by FastAPI routes
- `/health` checks Postgres connectivity alongside OpenSearch (closes the gap noted in `routers/health.py`'s own comment)
**Files likely to change:**
- `backend/requirements.txt`
- `backend/app/db/postgresql.py`
- `backend/app/routers/health.py`
- `docker-compose.yml`

#### SS-008 — Alembic migration bootstrap + base model conventions
**Description:** `backend/alembic.ini` already exists but `backend/migrations/versions/` is empty and no SQLAlchemy `Base`/model convention exists. Wire Alembic to the async engine and establish the base declarative model class.
**Priority:** Critical · **Effort:** S · **Dependencies:** SS-007
**Acceptance Criteria:**
- `alembic revision --autogenerate` and `alembic upgrade head` work against the compose Postgres service
- `backend/app/models/__init__.py` (currently empty) exports a shared `Base`
- A dummy first migration proves the pipeline works end-to-end
**Files likely to change:**
- `backend/migrations/env.py` (new/updated)
- `backend/app/models/__init__.py`
- `backend/migrations/versions/0001_*.py` (new)

#### SS-009 — Core `tenant` and `user` tables
**Description:** Define the first real SQLAlchemy models — `Tenant` and `User` (with `UserRole` from `core/enums.py`, bcrypt password hash column) — needed by Milestone 3's auth work.
**Priority:** Critical · **Effort:** M · **Dependencies:** SS-008
**Acceptance Criteria:**
- `Tenant` and `User` models exist with a migration
- `User.role` uses the existing `UserRole` enum, not a new literal
- Unique constraint on `(tenant_id, email)` for users
**Files likely to change:**
- `backend/app/models/tenant.py` (new)
- `backend/app/models/user.py` (new)
- `backend/migrations/versions/0002_*.py` (new)

#### SS-010 — Redis client module
**Description:** Implement `backend/app/db/redis.py` (currently empty) using `settings.redis_url`, add `redis` to `backend/requirements.txt`, add a `redis` service to compose.
**Priority:** High · **Effort:** XS · **Dependencies:** SS-001
**Acceptance Criteria:**
- Async Redis client factory available for import by correlation/session code
- `/health` includes a Redis check
**Files likely to change:**
- `backend/requirements.txt`
- `backend/app/db/redis.py`
- `backend/app/routers/health.py`
- `docker-compose.yml`

#### SS-011 — Celery app + broker wiring
**Description:** `backend/app/tasks/celery_app.py` is an empty stub with no broker configured. Wire it to Redis (already being added in SS-010), and add a worker service to compose so `tasks/`/`workers/` code in later milestones has somewhere to run.
**Priority:** High · **Effort:** S · **Dependencies:** SS-010
**Acceptance Criteria:**
- `celery -A app.tasks.celery_app worker` runs successfully against the Redis broker
- A trivial "hello world" task proves the pipeline end-to-end
- `docker-compose.yml` gains a `worker` service
**Files likely to change:**
- `backend/app/tasks/celery_app.py`
- `docker-compose.yml`
- `backend/requirements.txt` (`celery`)

---

## Milestone 3 — Authentication & Multi-Tenancy Enforcement

**Why now:** per `docs/architecture.md` §4, `tenant_id` is currently caller-supplied and unauthenticated — anyone can read or write any tenant's data. This is the highest-severity gap between the report's design and reality, and every user-facing feature after this point (incidents, reports, investigation) needs to know who's asking.

#### SS-012 — User registration + bcrypt password hashing
**Description:** Implement password hashing/verification (bcrypt via `passlib` or similar) and a registration flow creating `User` rows scoped to a `Tenant`.
**Priority:** Critical · **Effort:** M · **Dependencies:** SS-009
**Acceptance Criteria:**
- Passwords are never stored in plaintext or logged
- Duplicate email within a tenant is rejected with a clear error
- Unit tests cover hash/verify round-trip
**Files likely to change:**
- `backend/app/core/security.py`
- `backend/app/services/` (new `auth.py` or similar)
- `backend/requirements.txt` (`passlib[bcrypt]` or `bcrypt`)

#### SS-013 — JWT issuance & validation
**Description:** Implement `core/security.py` (currently empty) to issue/verify JWTs using `settings.JWT_SECRET`/`JWT_ALGORITHM`/`JWT_EXPIRY_HOURS`, embedding `tenant_id`, `user_id`, and `role` in the token claims.
**Priority:** Critical · **Effort:** M · **Dependencies:** SS-012
**Acceptance Criteria:**
- Token issued on successful login, verifiable and expiring per `JWT_EXPIRY_HOURS`
- Tampered/expired tokens are rejected with `401`
- `backend/requirements.txt` gains a JWT library (`python-jose` or `pyjwt`)
**Files likely to change:**
- `backend/app/core/security.py`
- `backend/requirements.txt`

#### SS-014 — Auth endpoints (`routers/v1/auth.py`)
**Description:** Implement the currently-empty `auth.py` router: `POST /api/v1/auth/register`, `POST /api/v1/auth/login`, `POST /api/v1/auth/refresh`.
**Priority:** Critical · **Effort:** M · **Dependencies:** SS-013
**Acceptance Criteria:**
- Endpoints registered in `main.py`
- Documented in `docs/api-design.md` (moved from "Planned" to "Implemented")
- Swagger UI (`/docs`) shows working examples
**Files likely to change:**
- `backend/app/routers/v1/auth.py`
- `backend/app/main.py`
- `docs/api-design.md`

#### SS-015 — Auth dependency injection (`core/dependencies.py`)
**Description:** Implement a FastAPI dependency that extracts and validates the JWT from the `Authorization` header, resolving it to a `(tenant_id, user_id, role)` context injectable into any route.
**Priority:** Critical · **Effort:** S · **Dependencies:** SS-013
**Acceptance Criteria:**
- `get_current_user()` (or similarly named) dependency usable via `Depends(...)` in any router
- Missing/invalid token → `401` before the route body executes
**Files likely to change:**
- `backend/app/core/dependencies.py`

#### SS-016 — Derive `tenant_id` from JWT on ingest & alerts
**Description:** Replace the current caller-supplied `tenant_id` in `POST /api/v1/ingest` and `GET /api/v1/alerts` with the authenticated value from SS-015, closing the isolation gap documented in `docs/architecture.md` §4.
**Priority:** Critical · **Effort:** S · **Dependencies:** SS-015
**Acceptance Criteria:**
- Both endpoints require a valid JWT; `tenant_id` in the request body/query is ignored or rejected if present and mismatched
- Test proves tenant A's token cannot read or write tenant B's data
- `docs/architecture.md` §4 updated to reflect enforcement is now real
**Files likely to change:**
- `backend/app/routers/v1/ingest.py`
- `backend/app/routers/v1/alerts.py`
- `docs/architecture.md`

#### SS-017 — RBAC enforcement (admin/analyst/viewer)
**Description:** Add a `require_role(...)` dependency (or decorator) enforcing the `UserRole` levels described in the SRS (§3.2): admins get full access, analysts get alert/incident/investigation access, viewers get read-only.
**Priority:** High · **Effort:** M · **Dependencies:** SS-015
**Acceptance Criteria:**
- At least one endpoint per role tier demonstrates enforcement (e.g., viewer blocked from a future write endpoint)
- 403 returned (not 401) when authenticated but under-privileged
**Files likely to change:**
- `backend/app/core/dependencies.py`

---

## Milestone 4 — Source Adapters & Ingestion Hardening

**Why now:** the ingestion pipeline only ever sees `synthetic` data today; without real adapters, every downstream feature (enrichment, correlation, risk scoring) can only ever be demonstrated on fake data.

#### SS-018 — Wazuh adapter
**Description:** Implement `backend/app/adapters/wazuh.py` (new — `adapters/` currently only has an empty `__init__.py`) to transform a raw Wazuh alert JSON payload into `NormalizedLog` fields, mapping Wazuh rule IDs to `mitre_technique`/`mitre_tactic` where available.
**Priority:** High · **Effort:** M · **Dependencies:** none (can start anytime after Milestone 1)
**Acceptance Criteria:**
- Given a sample real Wazuh alert JSON, produces a valid `NormalizedLog`
- Missing/unmappable fields degrade gracefully (log accepted with nulls, not rejected)
- Unit test with at least 2 sample Wazuh alert fixtures
**Files likely to change:**
- `backend/app/adapters/wazuh.py` (new)
- `backend/tests/test_adapters.py` (new)

#### SS-019 — AWS CloudTrail adapter
**Description:** Implement `backend/app/adapters/cloudtrail.py` (new) to transform a CloudTrail event record into `NormalizedLog` (`log_type="cloud"`, `source="aws_cloudtrail"`).
**Priority:** Medium · **Effort:** M · **Dependencies:** none
**Acceptance Criteria:**
- Given a sample CloudTrail event JSON, produces a valid `NormalizedLog`
- Actor/IP/resource fields map to `user`/`source_ip`/`description` sensibly
**Files likely to change:**
- `backend/app/adapters/cloudtrail.py` (new)
- `backend/tests/test_adapters.py`

#### SS-020 — AWS GuardDuty adapter
**Description:** Implement `backend/app/adapters/guardduty.py` (new) to transform a GuardDuty finding into `NormalizedLog` (`source="aws_guardduty"`), mapping GuardDuty severity (0.1–8.9 float) to the `Severity` enum.
**Priority:** Medium · **Effort:** M · **Dependencies:** none
**Acceptance Criteria:**
- Given a sample GuardDuty finding JSON, produces a valid `NormalizedLog`
- Severity float-to-enum mapping documented and tested at the boundaries
**Files likely to change:**
- `backend/app/adapters/guardduty.py` (new)
- `backend/tests/test_adapters.py`

#### SS-021 — Adapter dispatch wired into ingestion
**Description:** `services/ingestion.py` currently does no per-source transformation. Add a registry that dispatches to the correct adapter (SS-018/019/020) based on the `source` field before schema validation.
**Priority:** High · **Effort:** S · **Dependencies:** SS-018, SS-019, SS-020
**Acceptance Criteria:**
- `POST /api/v1/ingest` with `source: "wazuh"` (etc.) routes raw payloads through the matching adapter before validation
- Unknown `source` values fail clearly rather than silently falling through to the synthetic path
- `docs/architecture.md` §2.2 updated — adapters moved from Stub to Implemented
**Files likely to change:**
- `backend/app/services/ingestion.py`
- `docs/architecture.md`

---

## Milestone 5 — Threat Intelligence Enrichment

#### SS-022 — VirusTotal client
**Description:** Implement `backend/app/clients/virustotal.py` (currently empty) — IP and file-hash reputation lookups against the VT API, respecting `VT_RATE_LIMIT_PER_MINUTE`.
**Priority:** High · **Effort:** M · **Dependencies:** none
**Acceptance Criteria:**
- Client returns a normalized result matching the `TIResult` shape already defined in `schemas/log.py`
- Rate limiting enforced client-side (not just documented)
- Network failures raise a typed, catchable exception rather than propagating raw `requests` errors
**Files likely to change:**
- `backend/app/clients/virustotal.py`
- `backend/tests/test_clients.py` (new, with mocked HTTP)

#### SS-023 — AbuseIPDB client
**Description:** Implement `backend/app/clients/abuseipdb.py` (currently empty) — IP reputation lookups, respecting `ABUSEIPDB_RATE_LIMIT_PER_DAY`.
**Priority:** High · **Effort:** S · **Dependencies:** none
**Acceptance Criteria:**
- Same shape/behavior contract as SS-022
- Daily rate limit tracked (in-process counter is acceptable for Phase 2; Redis-backed is a stretch goal)
**Files likely to change:**
- `backend/app/clients/abuseipdb.py`
- `backend/tests/test_clients.py`

#### SS-024 — Threat intel cache table
**Description:** Add a `ti_cache` Postgres table (indicator, provider, result JSON, `is_malicious`, `expires_at`) implementing the cache-before-call behavior described in the SRS (§3.3): 7-day TTL for malicious indicators, 24-hour for clean.
**Priority:** High · **Effort:** S · **Dependencies:** SS-008
**Acceptance Criteria:**
- Migration adds the table
- TTL values read from `TI_CACHE_MALICIOUS_TTL`/`TI_CACHE_CLEAN_TTL` config, not hardcoded
**Files likely to change:**
- `backend/app/models/ti_cache.py` (new)
- `backend/migrations/versions/000X_*.py` (new)

#### SS-025 — Enrichment service
**Description:** Implement `backend/app/services/enrichment.py` (currently empty): given a `NormalizedLog` with an IP/hash/domain, check cache first (SS-024), call the appropriate client (SS-022/023) on a miss, write back to cache and to the OpenSearch document's `ti_result`/`ti_enriched`/`risk_score` fields.
**Priority:** High · **Effort:** M · **Dependencies:** SS-022, SS-023, SS-024
**Acceptance Criteria:**
- Cache hit path makes zero external HTTP calls (verified by test with mocked clients)
- External API outage doesn't raise past the service boundary — falls back to cached/no-op per SRS §3.4
**Files likely to change:**
- `backend/app/services/enrichment.py`

#### SS-026 — Async enrichment wired post-ingestion
**Description:** Trigger SS-025 as a Celery task after a log is accepted by `/api/v1/ingest`, so enrichment never blocks the ingestion response (per ADR-005 in `docs/decisions.md`, which currently holds true only because no enrichment code exists yet).
**Priority:** High · **Effort:** S · **Dependencies:** SS-011, SS-025
**Acceptance Criteria:**
- Ingestion response time is unaffected by enrichment latency (measured, not assumed)
- Enriched documents are updated in OpenSearch after the fact (update-by-id)
- `docs/decisions.md` ADR-005 updated to reflect this is now real async deferral, not accidental absence
**Files likely to change:**
- `backend/app/tasks/enrichment.py`
- `backend/app/routers/v1/ingest.py`
- `docs/decisions.md`

---

## Milestone 6 — Attack Chain Correlation Engine

#### SS-027 — Redis sliding window primitives
**Description:** Implement per-endpoint, per-tenant sliding-window storage in Redis (sorted sets keyed by `tenant_id:host_id`, 1-hour TTL per `CORRELATION_WINDOW_TTL`) that later pattern detectors can query.
**Priority:** High · **Effort:** M · **Dependencies:** SS-010
**Acceptance Criteria:**
- Adding an event to a window and querying "events for host X in last N minutes" both work
- Old entries expire automatically (verified with a time-manipulated test, not a real 1-hour wait)
**Files likely to change:**
- `backend/app/services/correlation.py`

#### SS-028 — Correlation pattern detectors (6 patterns)
**Description:** Implement the six attack patterns from the SRS (§3.3): credential brute force, successful compromise, recon-to-exploitation, privilege escalation, data exfiltration, lateral movement — each as a function evaluating a host's sliding window (SS-027) against a rule.
**Priority:** High · **Effort:** L · **Dependencies:** SS-027
**Acceptance Criteria:**
- Each pattern has at least one synthetic-log test fixture that triggers it and one that doesn't (true/false positive check)
- Confidence score computed per detected chain, compared against `CORRELATION_CONFIDENCE_THRESHOLD`
**Files likely to change:**
- `backend/app/services/correlation.py`
- `backend/tests/test_correlation.py` (new)

#### SS-029 — MITRE ATT&CK technique/tactic mapping table
**Description:** Build a lookup table (static data file or Postgres table) mapping detected pattern types to MITRE ATT&CK technique/tactic IDs, referenced by SS-028's output.
**Priority:** Medium · **Effort:** S · **Dependencies:** none
**Acceptance Criteria:**
- Each of the 6 patterns in SS-028 resolves to at least one technique ID
- Mapping is data, not inline strings scattered through `correlation.py`
**Files likely to change:**
- `backend/app/services/correlation.py` (or a new `backend/app/core/mitre_mapping.py`)

#### SS-030 — Correlation worker
**Description:** Implement `backend/app/workers/correlation_worker.py` (currently empty) — a Celery task or long-running consumer that runs SS-028's detectors against every newly ingested alert, per the "within seconds of ingestion" requirement (SRS §3.3).
**Priority:** High · **Effort:** M · **Dependencies:** SS-011, SS-028
**Acceptance Criteria:**
- Worker is triggered automatically on ingestion (not manually invoked)
- End-to-end test: inject a known brute-force sequence via the injector (see SS-064), confirm a chain is detected within a few seconds
**Files likely to change:**
- `backend/app/workers/correlation_worker.py`
- `backend/app/routers/v1/ingest.py`

#### SS-031 — Auto-create incident + dashboard notification on chain detection
**Description:** When SS-030 detects a chain above the confidence threshold, automatically create a linked incident (depends on Milestone 7's incident model) and push a notification (WebSocket, once the frontend exists — see Milestone 12).
**Priority:** Medium · **Effort:** S · **Dependencies:** SS-030, SS-035 (incident model)
**Acceptance Criteria:**
- A detected chain results in exactly one incident, not a duplicate per alert in the chain
- Incident references all contributing `alert_id`s
**Files likely to change:**
- `backend/app/workers/correlation_worker.py`
- `backend/app/services/` (incident creation helper)

---

## Milestone 7 — Endpoint Risk Scoring & Incident Management

#### SS-032 — Risk scoring service
**Description:** Implement `backend/app/services/risk_scoring.py` (currently empty) using the weight constants already defined in `core/config.py` (`RISK_SCORE_CRITICAL/HIGH/MEDIUM/LOW`, TI/anomaly/after-hours/MITRE bonuses, time decay).
**Priority:** High · **Effort:** M · **Dependencies:** SS-025 (enrichment feeds risk), SS-028 (correlation feeds risk)
**Acceptance Criteria:**
- Given a set of alerts for a host, produces a 0–100 score matching the documented formula
- Time decay (`RISK_TIME_DECAY_PER_HOUR`) reduces score for hosts with no recent activity, verified by test
- Score maps to the four risk levels (Low/Medium/High/Critical) per SRS §3.3
**Files likely to change:**
- `backend/app/services/risk_scoring.py`
- `backend/tests/test_risk_scoring.py` (new)

#### SS-033 — Scheduled risk recalculation task
**Description:** Implement `backend/app/tasks/scoring.py` (currently empty) as a periodic Celery beat task recalculating all endpoint scores (needed for the time-decay behavior in SS-032 to actually manifest over time, not just at alert-ingestion time).
**Priority:** Medium · **Effort:** S · **Dependencies:** SS-011, SS-032
**Acceptance Criteria:**
- Runs on a configurable interval, updates stored scores for all known endpoints
**Files likely to change:**
- `backend/app/tasks/scoring.py`

#### SS-034 — Endpoints listing API
**Description:** Implement `backend/app/routers/v1/endpoints.py` (currently empty): `GET /api/v1/endpoints` returning known hosts with current risk score/level, sorted by risk descending.
**Priority:** High · **Effort:** S · **Dependencies:** SS-032, SS-016 (tenant-scoped)
**Acceptance Criteria:**
- Endpoint requires auth, scoped to the caller's tenant
- Documented in `docs/api-design.md` (moved from Planned to Implemented)
**Files likely to change:**
- `backend/app/routers/v1/endpoints.py`
- `backend/app/main.py`
- `docs/api-design.md`

#### SS-035 — Incident model + migration
**Description:** Add an `Incident` Postgres model: status (`IncidentStatus` enum), linked `alert_id`s, timestamps, assigned analyst, audit trail of state transitions.
**Priority:** High · **Effort:** M · **Dependencies:** SS-008, SS-009
**Acceptance Criteria:**
- Every state transition is recorded with timestamp + acting user (SRS §3.3 audit requirement)
- Migration applies cleanly
**Files likely to change:**
- `backend/app/models/incident.py` (new)
- `backend/migrations/versions/000X_*.py` (new)

#### SS-036 — Incident CRUD + lifecycle endpoints
**Description:** Implement `backend/app/routers/v1/incidents.py` (currently empty): create, list, get, and transition (`open` → `investigating` → `resolved`/`false_positive`) endpoints.
**Priority:** High · **Effort:** M · **Dependencies:** SS-035, SS-016
**Acceptance Criteria:**
- Invalid state transitions (e.g. `resolved` → `open` directly, if disallowed by design) are rejected
- Manual incident creation (not just auto-created by correlation) works
**Files likely to change:**
- `backend/app/routers/v1/incidents.py`
- `backend/app/main.py`
- `docs/api-design.md`

#### SS-037 — Alert linking & investigation notes
**Description:** Extend incidents with the ability to link additional alerts after creation and append timestamped analyst notes, per SRS §3.3.
**Priority:** Medium · **Effort:** S · **Dependencies:** SS-036
**Acceptance Criteria:**
- Notes are immutable once posted (append-only) with author + timestamp
- Linking an alert twice is idempotent, not a duplicate row
**Files likely to change:**
- `backend/app/models/incident.py`
- `backend/app/routers/v1/incidents.py`

---

## Milestone 8 — CloudLens Integration

**Context:** CloudLens (`cloud/`) is a fully working, separate application. This milestone is entirely about bridging it into SafeSOC's unified alert queue — no changes to CloudLens's own scanning logic are anticipated.

#### SS-038 — CloudLens `Finding` → `NormalizedLog` adapter
**Description:** Implement a transform from CloudLens's `Finding` model (`category`, `title`, `description`, `severity`, `affected_resource`, `remediation` — see `cloud/AWS-IAM-backend/core/models.py`) into `NormalizedLog` (`log_type="cloud"`, `source="aws_cloudtrail"` or a new dedicated source value).
**Priority:** Medium · **Effort:** M · **Dependencies:** none (CloudLens's shape is stable)
**Acceptance Criteria:**
- Given a sample `Finding`, produces a valid `NormalizedLog` with `severity` correctly mapped (CloudLens uses `CRITICAL/HIGH/MEDIUM/LOW`; SafeSOC's `Severity` enum also has `low/medium/high/critical` — confirm case/value mapping explicitly, don't assume it matches)
- `remediation` text preserved somewhere on the normalized record (e.g. appended to `description` or a new optional field)
**Files likely to change:**
- `backend/app/adapters/cloudlens.py` (new)
- `backend/app/schemas/log.py` (only if a new optional field is genuinely needed)

#### SS-039 — Sync mechanism: CloudLens findings → `/api/v1/ingest`
**Description:** Build the bridge that actually moves data — either CloudLens's Django backend calls SafeSOC's `/api/v1/ingest` after a scan completes (push), or SafeSOC polls CloudLens's API on a schedule (pull). Push is simpler given CloudLens already has a notification hook (`engine/notifier.py`) to model this after.
**Priority:** Medium · **Effort:** M · **Dependencies:** SS-038, SS-016 (needs a service-level auth mechanism, not a user JWT)
**Acceptance Criteria:**
- A completed CloudLens scan results in its findings appearing in SafeSOC's alert queue within a defined time bound
- Failure to reach SafeSOC doesn't break the CloudLens scan itself (same fire-and-forget resilience as `notifier.py`'s Telegram integration)
**Files likely to change:**
- `cloud/AWS-IAM-backend/engine/` (new notifier-style module, e.g. `safesoc_bridge.py`) — note: this is the one piece of this milestone that touches `cloud/`, everything else stays in `backend/`
- `backend/app/routers/v1/cloud.py`

#### SS-040 — Cloud findings surfaced via `routers/v1/cloud.py`
**Description:** Implement the currently-empty `cloud.py` router — at minimum, a way to view/filter cloud-sourced alerts distinctly if needed, even though they now flow through the same `/api/v1/alerts` endpoint as everything else.
**Priority:** Low · **Effort:** S · **Dependencies:** SS-039
**Acceptance Criteria:**
- Cloud-sourced alerts are queryable via `GET /api/v1/alerts?source=aws_cloudtrail` (already supported by existing filter logic) — confirm this rather than reinventing it
- `cloud.py` only adds value beyond that if there's a cloud-specific view genuinely needed (e.g. summary stats) — don't build a redundant endpoint
**Files likely to change:**
- `backend/app/routers/v1/cloud.py`

#### SS-041 — Harmonize CloudLens risk score with SafeSOC risk scoring
**Description:** CloudLens computes its own 0–100 account-level risk score independently of SafeSOC's endpoint risk scoring (SS-032). Decide and implement how the two relate — e.g. CloudLens's score contributes to a tenant-level rollup, or cloud findings' severities feed into `risk_scoring.py`'s existing per-alert weighting.
**Priority:** Low · **Effort:** M · **Dependencies:** SS-032, SS-039
**Acceptance Criteria:**
- Documented decision (in `docs/decisions.md`) on how the two scores relate — this is a design choice, not just code
- Implementation matches the documented decision
**Files likely to change:**
- `backend/app/services/risk_scoring.py`
- `docs/decisions.md`

---

## Milestone 9 — Natural Language Investigation Assistant

#### SS-042 — Ollama client
**Description:** Implement `backend/app/clients/ollama.py` (currently empty) — HTTP client against a local Ollama instance (`settings.ollama_url`), running `OLLAMA_MODEL` (`mistral:7b` by default).
**Priority:** Medium · **Effort:** S · **Dependencies:** none
**Acceptance Criteria:**
- Given a prompt, returns a completion; connection failure raises a typed, catchable exception
**Files likely to change:**
- `backend/app/clients/ollama.py`

#### SS-043 — Groq client (cloud fallback)
**Description:** Implement `backend/app/clients/groq.py` (currently empty) as the cloud-based alternative when `LLM_PROVIDER=groq`.
**Priority:** Low · **Effort:** S · **Dependencies:** none
**Acceptance Criteria:**
- Same interface contract as SS-042, selectable via `settings.LLM_PROVIDER`
**Files likely to change:**
- `backend/app/clients/groq.py`

#### SS-044 — Intent classification (8 supported intents)
**Description:** Implement classification of a natural-language query into one of the 8 SRS-defined intents (auth failures, IP activity, endpoint snapshot, top alerts, user activity, cloud events, risky endpoints, attack chain status).
**Priority:** Medium · **Effort:** M · **Dependencies:** SS-042
**Acceptance Criteria:**
- Test set of representative queries per intent classifies correctly at a documented accuracy threshold (agree on a number, e.g. ≥80% on the test set, before calling this done)
- Unclassifiable queries have a defined fallback behavior (not a silent wrong answer)
**Files likely to change:**
- `backend/app/services/investigation.py`

#### SS-045 — MCP tool definitions for data retrieval
**Description:** Implement `backend/app/mcp/__init__.py` (currently empty) with typed tool definitions (one per intent from SS-044) that the LLM orchestrates calls to, per the report's stated architecture (§3.3) — the LLM should orchestrate pre-built queries, not generate raw database queries itself.
**Priority:** Medium · **Effort:** L · **Dependencies:** SS-044, SS-032 (risky-endpoints tool needs risk scoring), SS-031 (attack-chain-status tool needs correlation)
**Acceptance Criteria:**
- Each of the 8 intents has a corresponding tool with a defined input/output schema
- Tools query existing services (`risk_scoring`, `correlation`, `db.opensearch`) rather than duplicating query logic
**Files likely to change:**
- `backend/app/mcp/__init__.py`
- `backend/app/mcp/tools.py` (new)

#### SS-046 — Conversation context/session state
**Description:** Enable follow-up questions that reference previously discussed entities without restating them (SRS §3.3), requiring session state — likely Redis-backed given SS-010.
**Priority:** Medium · **Effort:** M · **Dependencies:** SS-010, SS-045
**Acceptance Criteria:**
- A two-turn conversation ("show failed logins for host X" → "what about yesterday?") resolves the second query using context from the first
- Session state expires after a reasonable idle period
**Files likely to change:**
- `backend/app/services/investigation.py`

#### SS-047 — Investigation endpoint
**Description:** Implement `backend/app/routers/v1/investigate.py` (currently empty): `POST /api/v1/investigate` accepting a natural-language query and conversation/session ID, returning the assistant's response.
**Priority:** Medium · **Effort:** S · **Dependencies:** SS-046
**Acceptance Criteria:**
- Meets the SRS's 15-second response time target under normal load (measured)
- Requires auth (SS-016), scoped to the caller's tenant
**Files likely to change:**
- `backend/app/routers/v1/investigate.py`
- `backend/app/main.py`
- `docs/api-design.md`

---

## Milestone 10 — Anomaly Detection

#### SS-048 — Synthetic normal-behavior training data generator
**Description:** Extend the injector or add a standalone script to generate 30 days of "normal" synthetic behavior (per SRS §3.3) suitable for unsupervised training — distinct from the attack-scenario generation in Milestone 13.
**Priority:** Medium · **Effort:** S · **Dependencies:** none
**Acceptance Criteria:**
- Generates a dataset with realistic diurnal/weekly patterns (not uniformly random), since Isolation Forest needs structure to learn "normal" from
**Files likely to change:**
- `injector/` (new script) or `ml/` (new training-data generator)

#### SS-049 — Isolation Forest training pipeline
**Description:** Add `scikit-learn` to `backend/requirements.txt`, build a training script that fits an Isolation Forest on SS-048's data and saves the model to `ANOMALY_MODEL_PATH` (`ml/model/isolation_forest.pkl`, per existing config).
**Priority:** Medium · **Effort:** M · **Dependencies:** SS-048
**Acceptance Criteria:**
- Trained model artifact saved to the exact path `core/config.py` already expects
- Training script documented (how to rerun it, what features it expects)
**Files likely to change:**
- `ml/train.py` (new)
- `backend/requirements.txt`

#### SS-050 — Anomaly scoring service
**Description:** Implement `backend/app/services/anomaly.py` (currently empty): load the SS-049 model, extract features from an alert (login patterns, connection diversity, process frequency, temporal features per SRS §3.3), score 0–1, flag if above `ANOMALY_THRESHOLD` (0.7).
**Priority:** Medium · **Effort:** M · **Dependencies:** SS-049
**Acceptance Criteria:**
- Feature extraction is documented and testable in isolation from the model
- Known-anomalous synthetic events score above threshold in a test; known-normal ones don't
**Files likely to change:**
- `backend/app/services/anomaly.py`

#### SS-051 — Z-score network volume spike detection
**Description:** Implement the statistical complement to SS-050 described in SRS §3.3 — Z-score analysis flagging sudden network traffic volume spikes (potential exfiltration), using `NETWORK_ANOMALY_ZSCORE_THRESHOLD`.
**Priority:** Low · **Effort:** S · **Dependencies:** SS-027 (reuses the sliding-window infra from correlation, if available by this point)
**Acceptance Criteria:**
- A synthetic volume spike triggers a flag; steady-state traffic doesn't
**Files likely to change:**
- `backend/app/services/anomaly.py`

---

## Milestone 11 — Automated Reporting & Notifications

#### SS-052 — PDF report generation
**Description:** Add `weasyprint` to `backend/requirements.txt`, implement `backend/app/services/reporting.py` (currently empty) to render the weekly digest described in SRS §3.3 (executive summary, alert trends, critical incidents, top-risk endpoints, TI findings, cloud posture, recommendations) to PDF, saved under `REPORT_OUTPUT_DIR`.
**Priority:** Medium · **Effort:** L · **Dependencies:** SS-032 (risk data), SS-036 (incident data), SS-025 (TI data), SS-039 (cloud posture data) — this issue is naturally last in its milestone since it aggregates everything else
**Acceptance Criteria:**
- Generates a valid PDF given a tenant's data for a date range
- Handles a tenant with zero incidents/alerts gracefully (no crash, sensible empty-state content)
**Files likely to change:**
- `backend/app/services/reporting.py`
- `backend/requirements.txt`

#### SS-053 — Weekly report scheduling
**Description:** Implement `backend/app/tasks/reporting.py` (currently empty) as a Celery beat task firing per `REPORT_SCHEDULE_DAY`/`REPORT_SCHEDULE_HOUR`, generating a report per tenant.
**Priority:** Medium · **Effort:** S · **Dependencies:** SS-011, SS-052
**Acceptance Criteria:**
- Runs automatically on schedule, not just on manual trigger
- One report per tenant per scheduled run, not duplicated
**Files likely to change:**
- `backend/app/tasks/reporting.py`

#### SS-054 — Reports listing/download endpoint
**Description:** Implement `backend/app/routers/v1/reports.py` (currently empty): list generated reports for the caller's tenant, download a specific one.
**Priority:** Medium · **Effort:** S · **Dependencies:** SS-052, SS-016
**Acceptance Criteria:**
- Tenant isolation enforced — cannot download another tenant's report by guessing an ID
**Files likely to change:**
- `backend/app/routers/v1/reports.py`
- `backend/app/main.py`
- `docs/api-design.md`

#### SS-055 — Telegram client for SafeSOC
**Description:** Implement `backend/app/clients/telegram.py` (currently empty) — SafeSOC's own Telegram notifier, structurally similar to CloudLens's existing `cloud/AWS-IAM-backend/engine/notifier.py` but for SafeSOC alerts/incidents rather than IAM findings. Don't share code across the two codebases (different stacks); mirror the pattern instead.
**Priority:** Low · **Effort:** S · **Dependencies:** none
**Acceptance Criteria:**
- Missing bot token/chat ID skips sending without erroring (same graceful-degradation behavior as CloudLens's version)
**Files likely to change:**
- `backend/app/clients/telegram.py`

#### SS-056 — Notification service + worker
**Description:** Implement `backend/app/services/notifications.py` and `backend/app/workers/notification_worker.py` (both currently empty) to push real-time critical-event notifications (per SRS §3.2's "SMB IT Administrator... receives immediate notification of critical events").
**Priority:** Low · **Effort:** M · **Dependencies:** SS-011, SS-055, SS-031 (chain detection is a notification trigger)
**Acceptance Criteria:**
- A critical-severity alert or new attack chain triggers a notification within a defined time bound
**Files likely to change:**
- `backend/app/services/notifications.py`
- `backend/app/workers/notification_worker.py`

---

## Milestone 12 — SafeSOC Frontend

**Note:** `frontend/` currently contains only `.gitkeep` — no framework decision has been made. CloudLens's frontend (React + TypeScript + Vite + Tailwind) is a reasonable default to match, for stack consistency and shared team familiarity, but this is a real decision to make explicitly, not just default into.

#### SS-057 — Frontend framework scaffold
**Description:** Decide and bootstrap the SafeSOC dashboard's frontend stack (recommend matching CloudLens: React + TS + Vite + Tailwind), with routing, an API client layer, and auth token storage/refresh wired to Milestone 3's endpoints.
**Priority:** Medium · **Effort:** M · **Dependencies:** SS-014 (needs working auth endpoints to build against)
**Acceptance Criteria:**
- `npm run dev` serves a working shell app that can log in against the real backend
- Documented in `docs/tech-stack.md` (moves frontend from "no stack chosen" to a concrete choice)
**Files likely to change:**
- `frontend/` (entire initial scaffold)
- `docs/tech-stack.md`

#### SS-058 — Auth/login UI
**Description:** Login form, token storage, auto-refresh, protected-route wrapper.
**Priority:** Medium · **Effort:** S · **Dependencies:** SS-057
**Acceptance Criteria:**
- Invalid credentials show a clear error; valid login redirects to the dashboard shell
**Files likely to change:**
- `frontend/src/pages/Login.tsx` (or equivalent, once scaffold exists)

#### SS-059 — Alert queue view
**Description:** Paginated, filterable alert list backed by `GET /api/v1/alerts`, matching the filters already supported server-side (severity, log_type, source, host, timerange).
**Priority:** Medium · **Effort:** M · **Dependencies:** SS-058
**Acceptance Criteria:**
- All existing backend filters are exposed in the UI, not a subset
**Files likely to change:**
- `frontend/src/pages/Alerts.tsx` (new)

#### SS-060 — Endpoint risk dashboard view
**Description:** View backed by `GET /api/v1/endpoints` (SS-034), sorted by risk, with drill-down to that endpoint's recent alerts.
**Priority:** Medium · **Effort:** M · **Dependencies:** SS-058, SS-034
**Acceptance Criteria:**
- Risk level (Low/Medium/High/Critical) is visually distinct, not just a number
**Files likely to change:**
- `frontend/src/pages/Endpoints.tsx` (new)

#### SS-061 — Incident management UI
**Description:** List, view, and transition incidents; link alerts; add notes — backed by Milestone 7's endpoints.
**Priority:** Medium · **Effort:** L · **Dependencies:** SS-058, SS-036
**Acceptance Criteria:**
- Lifecycle transitions in the UI match the backend's allowed state machine exactly (no UI-only states)
**Files likely to change:**
- `frontend/src/pages/Incidents.tsx` (new)

#### SS-062 — Investigation chat UI
**Description:** Chat interface backed by `POST /api/v1/investigate` (SS-047), maintaining the session/conversation ID across turns.
**Priority:** Medium · **Effort:** M · **Dependencies:** SS-058, SS-047
**Acceptance Criteria:**
- Follow-up questions visibly reuse context (matches SS-046's backend behavior)
**Files likely to change:**
- `frontend/src/pages/Investigate.tsx` (new)

#### SS-063 — Real-time updates (WebSocket)
**Description:** Add a WebSocket channel to the backend (`main.py`, currently REST-only) for pushing new-alert/new-incident/chain-detected events, consumed by the frontend for live dashboard updates without polling.
**Priority:** Low · **Effort:** L · **Dependencies:** SS-031, SS-057
**Acceptance Criteria:**
- A new critical alert appears in the open dashboard within a few seconds without a manual refresh
- Connection drop/reconnect handled gracefully on the frontend
**Files likely to change:**
- `backend/app/main.py`
- `backend/app/routers/` (new `ws.py` or similar)
- `frontend/src/` (WebSocket client hook)

---

## Milestone 13 — Synthetic Data & Demo Mode

#### SS-064 — Multi-scenario attack simulation in injector
**Description:** Extend `injector/injector.py` (currently generates only randomized `authentication`-type logs) to support named attack scenarios — brute force, lateral movement, data exfiltration, etc. — that produce sequences correlation (Milestone 6) is designed to detect. This closes the gap flagged in `docs/requirements.md` §3 between the report's claims and the actual injector.
**Priority:** Medium · **Effort:** M · **Dependencies:** none (useful immediately; especially valuable once SS-028 exists to test against)
**Acceptance Criteria:**
- At least the scenarios needed to exercise all 6 correlation patterns from SS-028 exist
- CLI accepts a `--scenario` argument; existing random-log behavior remains the default
**Files likely to change:**
- `injector/injector.py`

#### SS-065 — Demo mode
**Description:** Add a mode that pre-loads a coherent, historical dataset with active attack chains already present, for live demos/reviews (per SRS §3.3's "comprehensive demo mode").
**Priority:** Low · **Effort:** S · **Dependencies:** SS-064
**Acceptance Criteria:**
- One command loads a demo tenant with realistic alert history, at least one in-progress attack chain, and at least one resolved incident
**Files likely to change:**
- `injector/injector.py` (or a new `injector/demo.py`)

---

## Milestone 14 — Non-Functional Hardening & QA

#### SS-066 — Load/performance test harness
**Description:** Build a repeatable benchmark (e.g. `locust` or a simple async script) verifying the SRS's ≥100 events/sec ingestion and <500ms alert-query targets — currently unverified by any automated test (per `docs/requirements.md` §4).
**Priority:** Medium · **Effort:** M · **Dependencies:** SS-001 (needs a running stack to benchmark against)
**Acceptance Criteria:**
- Repeatable script/report showing actual measured throughput and query latency against the numbers in the SRS
- Documented in `docs/testing.md`, replacing the "Unverified" tag with real numbers (pass or fail — either is useful information)
**Files likely to change:**
- `backend/tests/perf/` (new) or `scripts/`
- `docs/testing.md`

#### SS-067 — Security review pass
**Description:** Review the implemented surface against OWASP Top 10 concerns — especially now that auth (Milestone 3) exists: injection risk in OpenSearch queries, JWT handling, secrets management, rate limiting on auth endpoints.
**Priority:** High · **Effort:** M · **Dependencies:** SS-013, SS-016 (needs auth to exist to review it)
**Acceptance Criteria:**
- Findings documented (even if the answer for some is "no issue found")
- Any Critical/High findings fixed or explicitly deferred with a linked follow-up issue
**Files likely to change:**
- Varies by finding

#### SS-068 — Full documentation sync pass
**Description:** After a significant chunk of this backlog lands, re-audit every file in `docs/` against the code (the same process used to write them originally) and update every Implemented/Partial/Planned tag that's changed.
**Priority:** Medium · **Effort:** M · **Dependencies:** should be repeated periodically, not just once — treat this as a recurring end-of-milestone task rather than a single issue in practice
**Acceptance Criteria:**
- No file in `docs/` claims a feature is Planned when it's actually shipped, or vice versa
**Files likely to change:**
- All of `docs/`

---

## Known Documentation Staleness (as of this roadmap)

Two prior documentation passes are now slightly out of sync with each other and should be reconciled as part of SS-068 (or sooner, informally):

- `docs/deployment.md` and `docs/testing.md` still describe `.env.example` and `.github/workflows/ci.yml` as empty/missing — both were populated in a later session and are no longer accurate.
- `docs/project-roadmap.md` (the higher-level, narrative roadmap) predates this file and lists "CI pipeline" and the root compose file together as outstanding — CI now has smoke-check jobs; the compose file (SS-001) is still genuinely missing. Read `docs/project-roadmap.md` as directionally correct but not field-accurate until it's updated.
