# SafeSOC — Coding Standards

This document describes the conventions actually followed in the implemented code (`backend/app/{core,db,schemas,routers,services}` and `injector/injector.py`), so Phase 2 work stays consistent with Phase 1. It is descriptive, not aspirational — where the codebase is inconsistent, that's called out rather than smoothed over.

## 1. Module Header Docstrings

Every implemented module opens with a short triple-quoted docstring: project name, then a one-line purpose statement. Example (`backend/app/db/opensearch.py`):

```python
"""
SafeSOC — OpenSearch Client
Connection management, index setup, bulk writes, and search queries.
"""
```

Follow this for any new module: `SafeSOC — <Component Name>` on the first line, one sentence describing responsibility on the second.

## 2. Directory Layout & Layering Rules

The backend follows a strict layering convention (visible in every implemented file, not just described in the report):

```
core/       shared config, enums, exceptions — no I/O
db/         database clients + query/write functions — no business rules
schemas/    Pydantic models — no I/O, no business rules
services/   business logic — orchestrates db/ and schemas/, called by routers
routers/    HTTP layer only — parses request, calls services/db, shapes response
adapters/   source-specific transformation into NormalizedLog (wazuh, cloudtrail, guardduty, cloudlens)
clients/    thin wrappers around external HTTP APIs (virustotal, abuseipdb, ollama, groq, telegram)
tasks/      Celery task definitions (enrichment, scoring, reporting, celery_app)
workers/    background consumers/loops (correlation_worker, notification_worker)
utils/      cross-cutting helpers (logging, etc.)
```

**Rule observed in the implemented code:** routers do not talk to OpenSearch directly except for simple read queries (`alerts.py` calls `db.opensearch.search_alerts` directly since there's no service layer needed for a pure query); anything with validation or write logic goes through a `services/` function (`ingest.py` → `services/ingestion.py` → `db/opensearch.py`). Keep this pattern for new endpoints: write-path logic belongs in `services/`, not in the router.

## 3. Configuration

All settings are centralized in `backend/app/core/config.py` as a single `pydantic_settings.BaseSettings` subclass, instantiated once as a module-level singleton (`settings = Settings()`) and imported wherever needed (`from app.core.config import settings`). Conventions observed:

- Settings are grouped with `# ── Section Name ──` comment banners.
- Every setting has a typed default — nothing is required to be set via environment for the app to boot.
- Derived values (URLs) are computed as `@property` on the `Settings` class (`postgres_url`, `redis_url`, `ollama_url`) rather than string-built inline elsewhere.
- New settings for a Phase 2 feature should be added to this file *and grouped under a clearly named section*, following the existing pattern — this repo's convention is to scaffold config ahead of the feature it serves (see `decisions.md` ADR-006), so add settings even before the consuming code exists.

## 4. Enums as the Vocabulary Source of Truth

Every fixed value set (log source, log type, severity, incident status, user role, TI provider, indicator type) is defined once in `backend/app/core/enums.py` as a `str, Enum` subclass, and referenced everywhere else (Pydantic schemas, OpenSearch mappings-as-string-literals, and — per the module docstring's stated intent — future SQLAlchemy models and frontend TypeScript types). New fixed vocabularies should be added here, not as inline string literals or ad hoc `Literal[...]` types scattered across files.

## 5. Schema Style (`schemas/`)

- One `NormalizedLog`-style Pydantic `BaseModel` per concept.
- Fields are grouped with `# ── Category ──` comment banners mirroring the categories in the SRS (Identity, Source, Timing, Host Context, Event Context, Detection, Network, File, Process, Enrichment) — see `database-schema.md` for the full mapping. New fields belong in the matching category, not appended at the end.
- Server-generated fields use `Field(default_factory=...)` (e.g. `alert_id: str = Field(default_factory=lambda: str(uuid4()))`).
- A `model_config["json_schema_extra"]["example"]` is provided on primary request/response schemas so they render usefully in Swagger UI.

## 6. Async Everywhere in the I/O Path

All router handlers and service functions that touch the database are `async def`, even where the underlying client call (`opensearch-py`'s `OpenSearch` client) is actually synchronous under the hood. Keep new I/O-adjacent functions `async def` for consistency with the existing call chain, even if a given client library is sync-only — this keeps FastAPI's event loop model uniform across the codebase and avoids a future rewrite when an async driver replaces a sync one (e.g. `asyncpg` for Postgres).

## 7. Logging

Use the structured JSON logger, not `print()` or the bare `logging` module directly:

```python
from app.utils.logger import get_logger
logger = get_logger(__name__)

logger.info("Batch ingested", accepted=len(accepted), rejected=len(rejected))
```

`get_logger()` returns a `StructuredLogger` (`backend/app/utils/logger.py`) whose methods accept a message plus arbitrary `**kwargs`, which are merged into a JSON object alongside `timestamp`, `level`, and `service`. Prefer structured kwargs (`logger.info("Batch ingested", accepted=5)`) over string interpolation (`logger.info(f"Accepted 5")`) so log fields stay machine-parseable.

## 8. Error Handling

`backend/app/core/exceptions.py` defines a `SafeSOCError` base exception with `IngestionError` (422) and `OpenSearchError` (503) subclasses, plus a `safesoc_exception_handler` FastAPI handler, registered once in `main.py` via `app.add_exception_handler(SafeSOCError, safesoc_exception_handler)` — registering the base class is sufficient to catch every subclass too, since Starlette walks the exception's MRO to find a handler. Routers raise the typed exceptions directly (e.g. `ingest.py` raises `IngestionError` for a malformed payload) rather than ad-hoc `HTTPException`s, so every SafeSOC-specific error produces the same `{"error": <message>, "status_code": <code>}` body. `OpenSearchError` is defined and wired into the handler but has no raise site yet — the ingestion path's OpenSearch I/O failures still propagate as an unhandled 500 rather than a clean 503; wiring that up is a natural follow-on, not yet done.

## 9. Validation Philosophy

Batch operations (`process_ingest_batch`) validate each item independently and continue on individual failure rather than aborting the whole batch — collect both an accepted list and a rejected list, and return both. Follow this pattern for any new batch-oriented endpoint rather than failing fast on the first bad item.

## 10. What's Not Yet Established

No linter, formatter, or type-checker config (e.g. `ruff`, `black`, `mypy`) exists in the repo yet — there's nothing to configure/enforce beyond the conventions above, which are inferred from reading the code, not from a style-checker. Consider adding one before Phase 2 accumulates more contributors and more code.
