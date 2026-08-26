# SafeSOC — Platform Observability

SS-077. Extends this project's existing structured logging (`app/utils/logger.py`, already in place since early Phase 1) with the two pillars it didn't have: metrics and request correlation ("structured tracing," in the roadmap's own wording). Deliberately scoped: this makes SafeSOC *observable* by exposing standard-format data — it does not bundle a metrics/dashboard/tracing backend (Prometheus server, Grafana, Jaeger) as a new service, since that would mean a new `docker-compose.yml` service this issue's own scope doesn't call for and this session's constraints didn't permit touching. Point your own Prometheus/Grafana at the endpoints below.

## What already existed (not duplicated)

- **Structured JSON logging** (`app/utils/get_logger`) — every backend module already logs via `StructuredLogger`, one JSON object per line (`timestamp`, `level`, `service`, `message`, plus arbitrary `**kwargs`). SS-077 extends this logger in place rather than adding a second logging system.
- **`GET /health`** — already checked OpenSearch/PostgreSQL/Redis connectivity (a pre-existing doc claiming only OpenSearch was checked was corrected in `docs/api-design.md` as part of this issue).

## What SS-077 adds

### 1. `GET /metrics` — Prometheus metrics

Standard Prometheus exposition format, via the `prometheus_client` library's default registry (no second/parallel registry). Point a Prometheus server's scrape config at it:

```yaml
scrape_configs:
  - job_name: safesoc-backend
    static_configs:
      - targets: ["your-safesoc-host:8000"]
```

Metrics exposed (in `app/utils/metrics.py`):

| Metric | Type | Labels | What it answers |
|---|---|---|---|
| `safesoc_http_requests_total` | Counter | `method`, `path`, `status_code` | Request volume and error rate per endpoint |
| `safesoc_http_request_duration_seconds` | Histogram | `method`, `path` | Latency distribution per endpoint |
| `safesoc_ingestion_logs_total` | Counter | `outcome` (`accepted`/`rejected`) | Ingestion health — a sudden rejection spike usually means a source adapter or an upstream log format changed |

Plus the Python client library's own default process/GC metrics (memory, GC pauses, etc.) — free, not custom-built here.

**`path` is the route *template*** (e.g. `/api/v1/incidents/{incident_id}`), never the raw path with a real ID interpolated — labeling by raw path would make this metric's cardinality grow without bound as new incidents/alerts/etc. are created, a classic Prometheus footgun this implementation deliberately avoids (`middleware/observability.py` reads `request.scope["route"].path`, populated by Starlette's router after `call_next()` resolves it).

A dashboard (Grafana or otherwise) reads from your own Prometheus instance scraping this endpoint — no dashboard is bundled in this repository.

### 2. Request correlation ("structured tracing")

`middleware/observability.py:ObservabilityMiddleware` assigns a request ID to every HTTP request — reusing an incoming `X-Request-ID` header if the caller (e.g. an upstream load balancer/gateway) already supplies one, generating a fresh UUID otherwise — and:

- Sets it in `app/utils/logger.py`'s `request_id_var` (a `contextvars.ContextVar`) for the duration of the request, so **every existing `logger.info()`/`.warning()`/etc. call anywhere in the codebase automatically includes `request_id` in its JSON output for that request** — no call site needed to change.
- Echoes it back as an `X-Request-ID` response header.

This means every log line produced while handling one request — across as many modules and background-task hops as that request touches — can be correlated by `grep`-ing (or, in a real log aggregator, filtering) for one `request_id`. Confirmed live: a single `POST /api/v1/ingest` call produced log lines from `services/ingestion.py` (two different log statements) and `db/opensearch.py` (a third), all three carrying the identical `request_id` automatically.

This is deliberately not full distributed tracing (no span hierarchy, no OpenTelemetry SDK/exporter, no trace-visualization backend) — that would need a new backend service (a collector) this issue's scope and this session's protected-files constraint (no `docker-compose.yml` changes) didn't call for. Request-ID correlation is the useful subset achievable without new infrastructure, and a natural upgrade path to full tracing later if genuinely needed (the same middleware is the natural place to add span creation).

## Why `backend/app/middleware/` is no longer empty

This directory existed as an empty stub since early in the project (see `CLAUDE.md`'s note that nothing needed it yet). HTTP-cross-cutting concerns — exactly what this issue needed — are exactly what ASGI middleware is for; `observability.py` is the first thing that's actually needed it.
