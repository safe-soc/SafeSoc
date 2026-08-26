"""
SafeSOC — Observability Tests (SS-077)
Covers the request-ID/metrics middleware, the /metrics endpoint, the
metric definitions themselves, and request_id_var's propagation into
structured log entries.
"""

import json

from prometheus_client import REGISTRY

from app.utils.logger import StructuredLogger, request_id_var
from app.utils.metrics import http_requests_total, ingestion_logs_total


def _counter_value(name: str, labels: dict) -> float:
    return REGISTRY.get_sample_value(name, labels) or 0.0


# ── GET /metrics ──────────────────────────────────────────────────────

def test_metrics_endpoint_returns_prometheus_exposition_format(client):
    response = client.get("/metrics")

    assert response.status_code == 200
    assert "text/plain" in response.headers["content-type"]
    assert b"safesoc_http_requests_total" in response.content


def test_metrics_endpoint_requires_no_authentication(client):
    """Consistent with /health — a scraper has no JWT to present."""
    response = client.get("/metrics")
    assert response.status_code == 200


# ── Request ID middleware ────────────────────────────────────────────

def test_response_includes_a_request_id_header(client):
    response = client.get("/metrics")

    assert "x-request-id" in response.headers
    assert response.headers["x-request-id"]  # non-empty


def test_an_incoming_request_id_is_echoed_back_unchanged(client):
    response = client.get("/metrics", headers={"X-Request-ID": "my-custom-trace-id"})

    assert response.headers["x-request-id"] == "my-custom-trace-id"


def test_two_requests_with_no_incoming_header_get_different_request_ids(client):
    response_a = client.get("/metrics")
    response_b = client.get("/metrics")

    assert response_a.headers["x-request-id"] != response_b.headers["x-request-id"]


# ── HTTP metrics recorded per request ────────────────────────────────

def test_a_request_increments_the_http_requests_total_counter(client):
    before = _counter_value("safesoc_http_requests_total", {"method": "GET", "path": "/metrics", "status_code": "200"})

    client.get("/metrics")

    after = _counter_value("safesoc_http_requests_total", {"method": "GET", "path": "/metrics", "status_code": "200"})
    assert after == before + 1


def test_the_recorded_path_label_is_the_route_template_not_a_raw_id(client):
    """A path with a path parameter (e.g. /api/v1/incidents/{id}) must be labeled by its template, not the literal UUID — unbounded cardinality otherwise."""
    import uuid

    before = _counter_value(
        "safesoc_http_requests_total",
        {"method": "GET", "path": "/api/v1/incidents/{incident_id}", "status_code": "401"},
    )

    client.get(f"/api/v1/incidents/{uuid.uuid4()}")  # no auth header -> 401, but routed and templated correctly

    after = _counter_value(
        "safesoc_http_requests_total",
        {"method": "GET", "path": "/api/v1/incidents/{incident_id}", "status_code": "401"},
    )
    assert after == before + 1


# ── Ingestion counter (services/ingestion.py) ────────────────────────

def test_ingestion_logs_total_has_accepted_and_rejected_label_values():
    """Regression guard: both label values used by services/ingestion.py must be valid for this counter."""
    ingestion_logs_total.labels(outcome="accepted")
    ingestion_logs_total.labels(outcome="rejected")


# ── request_id_var propagation into structured logs ──────────────────

def test_log_entry_includes_request_id_when_set(monkeypatch, capsys):
    logger = StructuredLogger("test-logger-1")
    token = request_id_var.set("test-request-id-123")
    try:
        logger.info("something happened")
    finally:
        request_id_var.reset(token)

    captured = capsys.readouterr()
    entry = json.loads(captured.out.strip().splitlines()[-1])
    assert entry["request_id"] == "test-request-id-123"


def test_log_entry_omits_request_id_when_not_set(capsys):
    logger = StructuredLogger("test-logger-2")
    assert request_id_var.get() is None  # no request in flight in this test

    logger.info("something happened outside a request")

    captured = capsys.readouterr()
    entry = json.loads(captured.out.strip().splitlines()[-1])
    assert "request_id" not in entry


def test_explicit_request_id_kwarg_overrides_the_context_value(capsys):
    logger = StructuredLogger("test-logger-3")
    token = request_id_var.set("from-context")
    try:
        logger.info("something happened", request_id="explicit-override")
    finally:
        request_id_var.reset(token)

    captured = capsys.readouterr()
    entry = json.loads(captured.out.strip().splitlines()[-1])
    assert entry["request_id"] == "explicit-override"
