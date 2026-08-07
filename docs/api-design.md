# SafeSOC — API Design

This document describes the actual FastAPI surface of `backend/app`. Endpoints are grouped into **Implemented** (working code, testable via `/docs`) and **Planned** (router file exists as an empty stub; shape below is inferred from the SRS, not from code — treat as a design proposal, not a contract).

Base URL (local dev): `http://localhost:8000`
Versioned prefix: `/api/v1` (`API_PREFIX` in `core/config.py`, though routers currently hardcode `/api/v1` in their own `prefix=` rather than reading that setting).

---

## Implemented Endpoints

### `GET /`

Root info. Defined inline in `backend/app/main.py`.

**Response 200**
```json
{ "name": "SafeSOC", "version": "1.0.0", "docs": "/docs" }
```

### `GET /health`

`backend/app/routers/health.py`. Pings OpenSearch only.

**Response 200**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "checks": { "opensearch": "connected" }
}
```
`status` becomes `"degraded"` if OpenSearch is unreachable. Postgres/Redis checks are not implemented — the code comment marks them as a future addition.

### `POST /api/v1/ingest`

`backend/app/routers/v1/ingest.py` → `services/ingestion.py` → `db/opensearch.py`.

**Request body** — one of:
```json
{ "log": { "...": "single NormalizedLog-shaped dict" } }
```
```json
{ "logs": [ { "...": "..." }, { "...": "..." } ], "tenant_id": "acme-corp", "source": "synthetic" }
```

- `tenant_id` and `source` at the top level are fallback defaults injected into each log if the log itself doesn't already carry them; if omitted entirely, `tenant_id` defaults to `"default-tenant"` and `source` to `"synthetic"`.
- **No authentication.** `tenant_id` is fully caller-controlled — see `architecture.md` §4.
- **Batch size cap enforced** at `settings.INGEST_BATCH_SIZE` (500 by default, not the SRS's stated 1,000 — the cap is config-driven, see `core/config.py`). A request with more logs than that returns `422` before any processing or writes happen (SS-005).

Each log is validated against `NormalizedLog` (see `database-schema.md` for the full field list). Invalid entries are rejected individually; valid entries in the same request still get written.

**Response 200**
```json
{
  "accepted": 2,
  "rejected": 0,
  "alert_ids": ["a1b2c3d4-...", "e5f6a7b8-..."],
  "errors": null
}
```
On partial failure, `errors` is a list of `{ "index": <int>, "error": "<pydantic message>", "raw": {...truncated fields...} }`.

**Error responses** (all via the registered `SafeSOCError`/`IngestionError` handler: `{"error": "<message>", "status_code": 422}`, not FastAPI's default `{"detail": ...}` shape — SS-004)
- `422` — payload has neither `"log"` nor `"logs"` key, or `"logs"` is not a list.
- `422` — `logs` exceeds `settings.INGEST_BATCH_SIZE` (500 by default) — SS-005.

### `GET /api/v1/alerts`

`backend/app/routers/v1/alerts.py` → `db/opensearch.py: search_alerts()`.

**Query parameters**

| Param | Required | Default | Notes |
|---|---|---|---|
| `tenant_id` | yes | — | Mandatory filter; no auth derives this automatically |
| `severity` | no | — | Exact match: `low`/`medium`/`high`/`critical` |
| `log_type` | no | — | Exact match against `LogType` enum |
| `source` | no | — | Exact match against `LogSource` enum |
| `host_id` | no | — | Exact match |
| `timerange_hours` | no | `24` | 1–720 |
| `page` | no | `1` | ≥1 |
| `size` | no | `50` | 1–500 |

**Response 200**
```json
{
  "total": 137,
  "page": 1,
  "size": 50,
  "pages": 3,
  "alerts": [ { "...": "NormalizedLog document" } ]
}
```
Results are sorted by `timestamp` descending and searched across all `safesoc-alerts-*` monthly indices.

### `POST /api/v1/auth/register`

`backend/app/routers/v1/auth.py` → `services/auth.py: register_user()` → `db/postgresql.py`.

**Request body**
```json
{ "tenant_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "email": "analyst@acme-corp.com", "password": "correct-horse-battery-staple", "role": "analyst" }
```
`role` is optional, defaulting to `"viewer"`. `tenant_id` must reference an existing `Tenant` row (SS-009) — this endpoint does not create tenants.

**Response 201**
```json
{ "id": "...", "tenant_id": "...", "email": "analyst@acme-corp.com", "role": "analyst" }
```
The password is hashed with bcrypt before storage (SS-012) and never appears in the response.

**Error responses**
- `409` — a user with this email already exists for this tenant (`DuplicateEmailError`).

### `POST /api/v1/auth/login`

`backend/app/routers/v1/auth.py` → `db/postgresql.py` (direct query) + `core/security.py`.

**Request body**
```json
{ "tenant_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "email": "analyst@acme-corp.com", "password": "correct-horse-battery-staple" }
```

**Response 200**
```json
{ "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", "token_type": "bearer" }
```
The token embeds `tenant_id`, `user_id`, and `role` claims and expires per `settings.JWT_EXPIRY_HOURS` (SS-013).

**Error responses**
- `401` — no matching user for `tenant_id`/`email`, or the password doesn't verify (`InvalidCredentialsError`; the same generic message either way, so login doesn't reveal whether an email exists).

### `POST /api/v1/auth/refresh`

`backend/app/routers/v1/auth.py` → `core/security.py`.

**Request body**
```json
{ "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." }
```

**Response 200** — same shape as `/login`, a freshly-issued token carrying the same `tenant_id`/`user_id`/`role` claims with a new expiry.

**Error responses**
- `401` — the supplied token is missing, tampered, or already expired (`InvalidTokenError`).

### `POST /api/v1/incidents`

`backend/app/routers/v1/incidents.py` → `services/incidents.py: create_incident()` → `db/postgresql.py`. Requires `analyst` role or higher.

**Request body**
```json
{ "alert_ids": ["alert-1", "alert-2"] }
```
`alert_ids` is optional, defaulting to `[]` — manual creation doesn't require pre-existing alerts. Always opens with `status: "open"` and records the creation itself as the first audit-trail transition (`from_status: null` → `to_status: "open"`).

**Response 201**
```json
{ "id": "...", "tenant_id": "...", "status": "open", "alert_ids": ["alert-1", "alert-2"], "assigned_analyst_id": null, "created_at": "...", "updated_at": "..." }
```

**Error responses**
- `403` — authenticated role is below `analyst` (`InsufficientRoleError`).

### `GET /api/v1/incidents`

`backend/app/routers/v1/incidents.py` → `services/incidents.py: list_incidents()`. Any authenticated role.

**Query parameters**

| Param | Required | Default | Notes |
|---|---|---|---|
| `status` | no | — | Exact match against `IncidentStatus` |
| `page` | no | `1` | ≥1 |
| `size` | no | `50` | 1–500 |

**Response 200** — same paginated shape as `GET /api/v1/alerts`, with an `incidents` array instead of `alerts`, sorted by `created_at` descending.

### `GET /api/v1/incidents/{incident_id}`

`backend/app/routers/v1/incidents.py` → `services/incidents.py: get_incident()`. Any authenticated role.

**Response 200** — single incident, same shape as the create response.

**Error responses**
- `404` — no incident with this id exists for the authenticated tenant (`IncidentNotFoundError`) — including one that exists under a *different* tenant, so a caller can't distinguish "not found" from "not yours."

### `POST /api/v1/incidents/{incident_id}/transitions`

`backend/app/routers/v1/incidents.py` → `services/incidents.py: transition_incident()`. Requires `analyst` role or higher.

**Request body**
```json
{ "to_status": "investigating" }
```

Lifecycle state machine (SS-036) — the only path is `open` → `investigating` → `resolved`/`false_positive`. No skipping ahead (`open` → `resolved` directly) and no backward moves (e.g. `resolved` → `open`); `resolved`/`false_positive` are terminal.

**Response 200** — the updated incident. Each successful transition also appends an `IncidentStateTransition` audit row recording `from_status`, `to_status`, the acting `changed_by_user_id`, and a timestamp (SRS §3.3).

**Error responses**
- `403` — authenticated role is below `analyst`.
- `404` — incident doesn't exist for this tenant.
- `409` — the requested `to_status` isn't reachable from the incident's current status (`InvalidStateTransitionError`).

### `GET /api/v1/endpoints`

`backend/app/routers/v1/endpoints.py` → `services/risk_scoring.py: list_endpoints()`. Any authenticated role.

Lists known hosts (`endpoints` table, upserted by the scheduled recalculation task, SS-033) for the authenticated tenant, sorted by `risk_score` descending.

**Response 200**
```json
[
  { "id": "...", "tenant_id": "...", "host_id": "WEB-SERVER-01", "risk_score": 80, "risk_level": "critical", "updated_at": "..." },
  { "id": "...", "tenant_id": "...", "host_id": "DESKTOP-042", "risk_score": 20, "risk_level": "low", "updated_at": "..." }
]
```
An empty list if the tenant has no known endpoints yet (no alerts have been scored for any host).

### `POST /api/v1/investigate`

`backend/app/routers/v1/investigate.py` → `services/investigation.py` (SS-044 classify_intent, SS-046 resolve_query) → `mcp/tools.py` (SS-045) → `clients/ollama.py` or `clients/groq.py` (SS-042/SS-043, selected by `settings.LLM_PROVIDER`). Any authenticated role.

Natural-language security queries, orchestrated rather than free-form: the query is classified into one of 8 supported intents, resolved against the conversation's prior context if it's a follow-up, routed to the matching pre-built MCP tool (never a raw LLM-generated database query, per the report's §3.3 architecture), and the tool's structured result is handed to the configured LLM to phrase as a conversational answer.

**Request body**
```json
{ "query": "Show me failed logins for host DESKTOP-042", "session_id": null }
```
`session_id` is optional — omit it (or pass `null`) to start a new conversation; a fresh one is generated and returned. Pass a previous response's `session_id` back to ask a follow-up that can reference what was already discussed (SS-046) — e.g. "what about yesterday?" after asking about a specific host.

**Response 200**
```json
{
  "session_id": "3fae8f0a-...",
  "intent": "auth_failures",
  "answer": "There were 2 failed login attempts on DESKTOP-042 in the last 24 hours.",
  "data": { "total": 2, "alerts": [ { "...": "matching alert documents" } ] }
}
```
`data` is the raw structured result from the intent's MCP tool (shape varies by intent — see `mcp/tools.py`'s per-tool output models). A query that doesn't classify into any of the 8 supported intents returns `intent: "unknown"`, an explanatory `answer`, and `data: {}` — not a silently wrong guess.

**Response time (SRS target: 15s).** The LLM answer-generation step is bounded by `settings.INVESTIGATION_LLM_TIMEOUT_SECONDS` (10s default); if the configured LLM is slow, unreachable, or errors, the endpoint degrades to a templated summary of the tool's data instead of failing or blocking the response — classification, context resolution, and the tool query itself are the only unavoidable latency, and are normally sub-second.

### `GET /api/v1/reports`

`backend/app/routers/v1/reports.py` → `services/reporting.py: list_reports()`. Any authenticated role.

Lists PDF security reports (SS-052, generated on a weekly schedule by SS-053, or on demand) for the authenticated tenant, newest first. Reports are stored under `settings.REPORT_OUTPUT_DIR/{tenant_id}/` — the filesystem path itself is the tenant-isolation boundary, not just a query filter.

**Response 200**
```json
{
  "reports": [
    { "filename": "20260807T060000Z.pdf", "generated_at": "2026-08-07T06:00:00Z", "size_bytes": 10983 }
  ]
}
```
An empty list if the tenant has no generated reports yet.

### `GET /api/v1/reports/{filename}`

`backend/app/routers/v1/reports.py` → `services/reporting.py: get_report_path()`. Any authenticated role.

Downloads a specific report as `application/pdf`. `filename` is resolved only inside the authenticated tenant's own report directory — a filename that exists under a *different* tenant's directory (even guessed exactly right) returns the same `404` as one that doesn't exist at all, and any `/`, `\`, or `..` in `filename` is rejected outright, so tenant isolation holds regardless of what's supplied.

**Response 404**
```json
{ "error": "Report '<filename>' not found.", "status_code": 404 }
```

---

## Planned Endpoints (stub routers, no logic)

These router files exist under `backend/app/routers/v1/` but are **empty** — no path operations are registered, and none of them are included in `main.py`. Shapes below are proposals derived from the SRS, not implementations.

| File | Intended purpose (SRS §3.3) |
|---|---|
| `cloud.py` | Surface CloudLens findings (or ingest them via the adapter pipeline) in the unified alert view |

`endpoints.py`, `investigate.py`, and `reports.py` are no longer stubs — `GET /api/v1/endpoints` (SS-034), `POST /api/v1/investigate` (SS-047), and `GET /api/v1/reports`(`/{filename}`) (SS-054) are all implemented (see above).

`incidents.py` is no longer a stub — CRUD and lifecycle transitions are implemented (see above); alert linking and investigation notes remain planned (SS-037).

Because the routers above aren't registered in `main.py`, hitting any of their implied paths today returns FastAPI's default `404`.

## API Documentation Access

Interactive Swagger UI is auto-generated by FastAPI at `/docs`, and ReDoc at `/redoc`, both gated behind `settings.DEBUG` (`True` by default in `core/config.py`). This is how the implemented endpoints above can be explored and tested without a frontend.
