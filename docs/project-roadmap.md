# SafeSOC — Project Roadmap

Source: Phase 1 report §7.4 ("Work Planned for Subsequent Phases"), cross-checked against what already has scaffolding in the repo.

## Phase 1 — Complete

Per the report and confirmed in code:

- [x] Core ingestion pipeline: `POST /api/v1/ingest`, `NormalizedLog` schema, OpenSearch bulk write
- [x] `GET /api/v1/alerts` query endpoint with tenant/severity/type/source/host filters
- [x] Monthly OpenSearch index creation + mapping
- [x] `GET /health` endpoint
- [x] Synthetic log injector (basic — single log type, no scenarios; see `requirements.md` §3)
- [x] Backend Dockerfile
- [x] CloudLens (AWS IAM analyzer) — fully functional standalone application

## Phase 2 — In Progress

- [x] Root `docker-compose.yml` for single-command SafeSOC backend deployment (SS-001) — see `docs/deployment.md`

## Phase 2 — Planned

Each item lists the report's stated goal alongside what scaffolding (if any) already exists for it.

| Goal | Existing scaffolding | Not yet done |
|---|---|---|
| Integrate PostgreSQL + Redis (complete 3-tier storage) | Connection settings + URL builders in `core/config.py`; empty `db/postgresql.py`, `db/redis.py` | Drivers not in `requirements.txt`; no models; no migrations |
| Automated threat intelligence enrichment + caching | `clients/virustotal.py`, `clients/abuseipdb.py`, `services/enrichment.py` exist as empty files; cache TTL settings defined | All actual logic |
| Attack chain correlation engine (Redis sliding windows, MITRE patterns) | `services/correlation.py`, `workers/correlation_worker.py` exist as empty files; `CORRELATION_WINDOW_TTL`/`CORRELATION_CONFIDENCE_THRESHOLD` defined | All actual logic; depends on Redis being implemented first |
| JWT auth, RBAC, multi-tenant enforcement | `UserRole` enum; JWT settings in config; `routers/v1/auth.py`, `core/security.py`, `core/dependencies.py` exist as empty files | All actual logic; `tenant_id` currently unauthenticated |
| Natural language investigation assistant (MCP) | `services/investigation.py`, `mcp/__init__.py`, `routers/v1/investigate.py`, `clients/ollama.py`, `clients/groq.py` exist as empty files; LLM provider settings defined | All actual logic; neither `ollama` nor `groq` client libs installed |
| React frontend (alert queue, endpoint views, investigation chat) | `frontend/` contains only `.gitkeep` | Everything — no framework chosen yet |
| Integrate CloudLens findings into unified alert stream | `routers/v1/cloud.py` exists as an empty file | The adapter that converts CloudLens findings to `NormalizedLog` and pushes them through `/api/v1/ingest` |

## Not Yet Scheduled (mentioned in SRS, no Phase 2 scaffolding beyond enums/config)

- Endpoint risk scoring (`services/risk_scoring.py`, `tasks/scoring.py` — empty)
- Incident management lifecycle (`routers/v1/incidents.py` — empty; no incident model)
- Anomaly detection / Isolation Forest (`services/anomaly.py` — empty; `ml/` directory empty; `scikit-learn` not installed)
- Automated PDF reporting (`services/reporting.py`, `tasks/reporting.py` — empty; WeasyPrint not installed)
- Notifications (`services/notifications.py`, `workers/notification_worker.py`, `clients/telegram.py` — empty)
- Index Lifecycle Management for OpenSearch (90-day retention)
- Automated backend test suite wired into CI (`.github/workflows/ci.yml` runs smoke checks only, not a real test suite; `backend/tests/` has no test cases yet)

## Immediate Next Steps (suggested ordering, not yet committed)

Given dependency order (later Phase 2 items depend on earlier infrastructure), a reasonable build sequence is:

1. ~~Root `docker-compose.yml` + populated `.env.example`~~ — **done** (SS-001), unblocking reliable local development.
2. PostgreSQL + Redis wiring (drivers, models, migrations) — required by almost everything else in Phase 2.
3. JWT auth + tenant enforcement — required before any multi-tenant feature can be trusted.
4. Threat intel enrichment — self-contained, doesn't depend on correlation or the NL assistant.
5. Correlation engine — depends on Redis.
6. Risk scoring — depends on enrichment + correlation for its inputs.
7. NL investigation assistant — depends on having real alert/incident data to query.
8. CloudLens integration into the unified alert stream.
9. Frontend.
10. Reporting, notifications, anomaly detection.

This ordering is a suggestion for planning purposes, not a decision recorded elsewhere in the repo — revisit as priorities shift.
