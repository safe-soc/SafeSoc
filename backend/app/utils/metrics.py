"""
SafeSOC — Prometheus Metrics (SS-077)
Metric definitions for platform observability. Deliberately minimal —
per-request HTTP counters/latency plus the two business counters
(ingestion accepted/rejected) that most directly answer "is the
platform healthy," not a large instrumentation surface. Scraped via
GET /metrics (routers/health.py), in the standard Prometheus
exposition format — an external Prometheus server/Grafana dashboard
is expected to point at that endpoint; neither is bundled in this
repository (no new docker-compose.yml service was added for this).

One shared `prometheus_client.REGISTRY` (the library's default) is
used throughout — no second/parallel metrics registry.
"""

from prometheus_client import Counter, Histogram

http_requests_total = Counter(
    "safesoc_http_requests_total",
    "Total HTTP requests handled, by method/path template/status code.",
    ["method", "path", "status_code"],
)

http_request_duration_seconds = Histogram(
    "safesoc_http_request_duration_seconds",
    "HTTP request duration in seconds, by method/path template.",
    ["method", "path"],
)

ingestion_logs_total = Counter(
    "safesoc_ingestion_logs_total",
    "Total logs processed by POST /api/v1/ingest, by outcome (accepted/rejected).",
    ["outcome"],
)
