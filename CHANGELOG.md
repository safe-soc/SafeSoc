# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning follows the pre-1.0 scheme described in `PRODUCT_ROADMAP.md`: breaking changes are expected between `v0.x.0` releases, each representing a release-worthy chunk of the Phase 2 backlog (`docs/roadmap-issues.md`) landing.

## [Unreleased]

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
