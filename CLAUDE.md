# CLAUDE.md

Guidance for Claude Code (or any agent) working in this repository.

## What this repository is

SafeSOC — an AI-assisted, multi-tenant Security Operations Platform for SMBs, built as a Major Project (Phase 1 complete) at SJB Institute of Technology. The full design spec is the Phase 1 report; the living record of what's actually built vs. planned is `docs/`. **When the two disagree, trust `docs/` and the code — the report describes the target, not necessarily the current state.**

## Repository state — read this first

- This is the **canonical, finalized** repository structure. Do not propose repo restructuring, directory moves, or renames unless explicitly asked. This has already been audited once; don't re-audit unprompted.
- `docs/` is the authoritative status record. Every file there follows an **Implemented / Partial / Planned** convention — check it before assuming a feature exists.
- A large fraction of `backend/app/` is **empty placeholder files** (0 bytes) — the directory layout for Phase 2 was scaffolded ahead of the code that will fill it. An empty file at the expected path is normal here, not a bug to "fix" by writing something into it unprompted.

## Repository layout

```
backend/          SafeSOC FastAPI backend — the real Phase 1 implementation
frontend/         SafeSOC React dashboard — not started (contains only .gitkeep)
injector/         Standalone synthetic log generator (injector.py) — implemented, basic
ml/               Anomaly detection model artifacts — empty, Phase 2
scripts/          Empty, Phase 2
cloud/            CloudLens — a separate, fully working AWS IAM risk analyzer
  AWS-IAM-backend/   Django + DRF + Boto3 + NetworkX
  AWS-IAM-frontend/  React + TypeScript + Vite
docs/             Project documentation — status source of truth (see below)
infrastructure/   Empty, Phase 2
assets/           Diagrams (architecture.drawio, er-diagram.drawio)
.github/          CI workflow, PR template, CODEOWNERS
```

## What's actually implemented (backend/)

Only these carry real logic: `core/config.py`, `core/enums.py`, `schemas/log.py` (the `NormalizedLog` schema), `db/opensearch.py`, `db/mappings/alert_mapping.py`, `services/ingestion.py`, `routers/health.py`, `routers/v1/ingest.py`, `routers/v1/alerts.py`, `main.py`, `utils/logger.py`, `core/exceptions.py` (defined but its handler isn't registered in `main.py`).

Everything else under `backend/app/` — `auth.py`, `cloud.py`, `endpoints.py`, `incidents.py`, `investigate.py`, `reports.py`, all of `clients/`, most of `services/`, all of `tasks/`, `workers/`, `mcp/`, `middleware/`, `models/`, `db/postgresql.py`, `db/redis.py`, `adapters/` — is an empty stub. `core/config.py` already defines settings for all of it (Postgres, Redis, JWT, LLM providers, TI APIs, correlation, risk scoring, anomaly detection, reporting), so don't infer a feature is live just because its config exists.

Full status tables: `docs/architecture.md`, `docs/requirements.md`, `docs/project-roadmap.md`.

## Known gaps to keep in mind

- **No authentication.** `tenant_id` is caller-supplied on every request, unauthenticated. Don't describe multi-tenancy as "secured" — the filtering logic is real, the trust boundary isn't.
- **Root `docker-compose.yml` exists** (backend + OpenSearch, healthcheck-gated startup) — `docker compose up --build` from repo root. `cloud/docker-compose.yml` remains a separate, CloudLens-only stack, not orchestrated together with the root one. See `docs/deployment.md`.
- **No automated tests.** `backend/tests/` has empty `__init__.py`/`conftest.py` only. `.github/workflows/ci.yml` runs import/build smoke checks, not a test suite.
- **`.env.example`** documents every setting `core/config.py` defines — most of it isn't consumed by any running code yet. Don't assume a documented env var implies a working integration.
- CloudLens (`cloud/`) is real and working but **not integrated** — its findings don't flow into SafeSOC's ingestion pipeline yet. `routers/v1/cloud.py` (the intended bridge) is an empty stub.

## Conventions to follow when writing backend code

(Full detail: `docs/coding-standards.md`)

- Module header docstrings: `SafeSOC — <Component Name>` + one-line purpose.
- Layering: `routers/` = HTTP only → `services/` = business logic → `db/` = queries/writes. Don't put write-path logic directly in a router.
- Fixed vocabularies go in `core/enums.py` as `str, Enum` — never inline string literals for things like severity or status.
- New settings go in `core/config.py`, grouped under a `# ── Section ──` banner, even before the feature that consumes them exists (this repo scaffolds config ahead of code — that's intentional here, not a mistake to avoid).
- Use `app.utils.logger.get_logger(__name__)` (structured JSON logs) instead of `print()` or bare `logging`.
- Batch operations validate each item independently and report partial success (`accepted`/`rejected` lists) rather than failing the whole batch on one bad item.

## Working in this repo

- Don't modify application code unless explicitly asked to — several recent sessions have been documentation-only (`docs/`, root project files). Check what the user is actually asking for.
- When updating `docs/`, keep the Implemented/Partial/Planned tagging discipline — never upgrade a feature's status without checking the code.
- The report's figures/screenshots reflect a point-in-time manual verification, not a reproducible test suite — don't cite them as proof a feature still works today without checking the code.
