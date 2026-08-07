# SafeSOC — Project Roadmap

Source: Phase 1 report §7.4 ("Work Planned for Subsequent Phases"), cross-checked against the current code. Superseded by `PRODUCT_ROADMAP.md` for forward-looking planning (see that file's "How the three roadmap documents relate" section) — this file is now primarily a historical record of Phase 1 → Phase 2 completion.

## Phase 1 — Complete

Per the report and confirmed in code:

- [x] Core ingestion pipeline: `POST /api/v1/ingest`, `NormalizedLog` schema, OpenSearch bulk write
- [x] `GET /api/v1/alerts` query endpoint with tenant/severity/type/source/host filters
- [x] Monthly OpenSearch index creation + mapping
- [x] `GET /health` endpoint
- [x] Synthetic log injector (basic — single log type, no scenarios yet at Phase 1)
- [x] Backend Dockerfile
- [x] CloudLens (AWS IAM analyzer) — fully functional standalone application

## Phase 2 — Complete

All 14 milestones of `docs/roadmap-issues.md` (SS-001 through SS-067) are implemented. See `CHANGELOG.md` for the full per-milestone breakdown and `docs/roadmap-issues.md` for per-issue completion dates.

- [x] Milestone 1 — Deployment Foundation & Test Bootstrap (SS-001–006)
- [x] Milestone 2 — Storage Tier: PostgreSQL, Redis, Celery (SS-007–011)
- [x] Milestone 3 — Authentication & Multi-Tenancy Enforcement (SS-012–017)
- [x] Milestone 4 — Source Adapters & Ingestion Hardening (SS-018–021)
- [x] Milestone 5 — Threat Intelligence Enrichment (SS-022–026)
- [x] Milestone 6 — Attack Chain Correlation Engine (SS-027–031)
- [x] Milestone 7 — Endpoint Risk Scoring & Incident Management (SS-032–037)
- [x] Milestone 8 — CloudLens Integration (SS-038–041)
- [x] Milestone 9 — Natural Language Investigation Assistant (SS-042–047)
- [x] Milestone 10 — Anomaly Detection (SS-048–051)
- [x] Milestone 11 — Automated Reporting & Notifications (SS-052–056)
- [x] Milestone 12 — SafeSOC Frontend (SS-057–063)
- [x] Milestone 13 — Synthetic Data & Demo Mode (SS-064–065)
- [x] Milestone 14 — Non-Functional Hardening & QA (SS-066–067; SS-068, this documentation-sync pass, recurs rather than closes out once)

## What's Left

Per `PRODUCT_ROADMAP.md`'s release plan (the forward-looking source of truth from here): `SS-070` (formal API versioning policy), `SS-071` (audit log), and `SS-072` (installer/setup script) are the only items from that document's `v1.0.0` scope not yet built — none of them are part of the original 68-issue `docs/roadmap-issues.md` backlog. `PRODUCT_ROADMAP.md`'s `v1.1+`/`v2.0` sections describe further open-source and research-grade work beyond that.
