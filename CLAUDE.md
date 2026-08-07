# CLAUDE.md

Guidance for Claude Code (or any agent) working in this repository.

## What this repository is

SafeSOC — an AI-assisted, multi-tenant Security Operations Platform for SMBs, built as a Major Project (Phase 1 complete) at SJB Institute of Technology. The full design spec is the Phase 1 report; the living record of what's actually built vs. planned is `docs/`. **When the two disagree, trust `docs/` and the code — the report describes the target, not necessarily the current state.**

## Repository state — read this first

- This is the **canonical, finalized** repository structure. Do not propose repo restructuring, directory moves, or renames unless explicitly asked. This has already been audited once; don't re-audit unprompted.
- `docs/` is the authoritative status record. Every file there follows an **Implemented / Partial / Planned** convention — check it before assuming a feature exists.
- **As of SS-068 (documentation sync), the full 68-issue roadmap through Milestone 14 is implemented** — `docs/roadmap-issues.md` marks SS-001 through SS-067 as done. `backend/app/middleware/` is the only genuinely-empty directory left in `backend/app/`; a handful of standalone future-work items (audit logging, an installer script, formal API versioning) tracked in `PRODUCT_ROADMAP.md` past SS-068 are the only things not yet built. An empty file elsewhere is a real gap worth flagging, not the default expectation it used to be.

## Repository layout

```
backend/          SafeSOC FastAPI backend — fully implemented (Milestones 1-14)
frontend/         SafeSOC React dashboard — implemented (Milestone 12, SS-057-063)
injector/         Standalone synthetic log generator + demo mode — implemented (SS-064/065)
ml/               Isolation Forest anomaly model: training data, training script, trained model — implemented (SS-048-051)
scripts/          Empty — no installer/setup script exists yet (see PRODUCT_ROADMAP.md)
cloud/            CloudLens — a separate, fully working AWS IAM risk analyzer, bridged into SafeSOC's ingestion pipeline (SS-038-041)
  AWS-IAM-backend/   Django + DRF + Boto3 + NetworkX
  AWS-IAM-frontend/  React + TypeScript + Vite
docs/             Project documentation — status source of truth (see below)
infrastructure/   Empty — no IaC exists yet
assets/           Diagrams (architecture.drawio, er-diagram.drawio)
.github/          CI workflow, PR template, CODEOWNERS
```

## What's implemented (backend/)

Every `backend/app/` subpackage carries real logic now — routers (`health`, `ingest`, `alerts`, `auth`, `incidents`, `cloud`, `endpoints`, `investigate`, `reports`, `ws`), `services/` (ingestion, enrichment, correlation, risk_scoring, incidents, investigation, anomaly, reporting, notifications, realtime, rate_limit), `workers/` (correlation_worker, notification_worker), `tasks/` (enrichment, scoring, reporting, celery_app), `clients/` (virustotal, abuseipdb, ollama, groq, telegram), `mcp/tools.py`, `adapters/` (wazuh, cloudtrail, guardduty, cloudlens), `models/` (tenant, user, incident, ti_cache, endpoint), and both `db/postgresql.py` and `db/redis.py`.

**`backend/app/middleware/` is the one exception** — still an empty stub. Nothing currently needs it; don't fill it in unprompted.

`core/config.py` defines settings for every feature above; each one is now actually consumed by the code that needs it (this used to not be true — check `docs/decisions.md` ADR-006 for the history, not the current state).

Full status tables: `docs/architecture.md`, `docs/requirements.md`, `docs/project-roadmap.md`, `docs/roadmap-issues.md`.

## Known gaps to keep in mind

- **Authentication is real.** JWT (register/login/refresh), bcrypt password hashing, and role-based access (`admin`/`analyst`/`viewer` via `core/dependencies.py::require_role`) are all implemented and enforced (SS-012-017). `tenant_id` is derived from the verified JWT, not caller-supplied. Login/register are rate-limited (SS-067). See `docs/security-review.md` for the full security posture, including what's still deliberately deferred (e.g. JWT refresh doesn't re-check the DB for user existence, no security-headers middleware).
- **Root `docker-compose.yml` exists** (OpenSearch + Postgres + Redis + backend + worker + beat, healthcheck-gated startup) — `docker compose up --build` from repo root. `cloud/docker-compose.yml` remains a separate, CloudLens-only stack, not orchestrated together with the root one. See `docs/deployment.md`.
- **545 automated backend tests exist and run in CI** (`backend/tests/`, `pytest`). `.github/workflows/ci.yml` runs install → import check → the real test suite, not just smoke checks.
- **`.env.example`** documents most settings `core/config.py` defines and is now largely accurate about what's `[ACTIVE]` vs consumed — but keep it in sync when adding new settings (see `docs/security-review.md`'s note on the SS-067 rate-limit settings as an example of ones that needed adding).
- CloudLens (`cloud/`) is real, working, **and integrated** — `POST /api/v1/cloud/findings` (service-token authenticated) routes its findings through the same ingestion pipeline as everything else (SS-038-040).
- The injector's standalone CLI (`injector/injector.py`) and `injector/demo.py` both authenticate before sending logs (BUG-001 fix) — running either against a fresh environment with no demo tenant provisioned yet will fail login with a clear error message directing you to run `demo.py` first, or to pass explicit `--tenant-id`/`--email`/`--password`.

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
