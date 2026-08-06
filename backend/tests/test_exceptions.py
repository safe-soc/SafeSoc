"""
SafeSOC — Exception Handling Tests
"""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.exceptions import IngestionError, OpenSearchError, SafeSOCError, safesoc_exception_handler


def _build_test_app() -> TestClient:
    """Minimal FastAPI app wiring only the SafeSOCError handler, isolating its behavior from any real route."""
    app = FastAPI()
    app.add_exception_handler(SafeSOCError, safesoc_exception_handler)

    @app.get("/raise-ingestion-error")
    async def _raise_ingestion_error():
        raise IngestionError("bad payload")

    @app.get("/raise-opensearch-error")
    async def _raise_opensearch_error():
        raise OpenSearchError("cluster unreachable")

    return TestClient(app)


def test_handler_produces_documented_shape_for_ingestion_error():
    response = _build_test_app().get("/raise-ingestion-error")

    assert response.status_code == 422
    assert response.json() == {"error": "bad payload", "status_code": 422}


def test_handler_produces_documented_shape_for_opensearch_error():
    response = _build_test_app().get("/raise-opensearch-error")

    assert response.status_code == 503
    assert response.json() == {"error": "cluster unreachable", "status_code": 503}


def test_ingest_missing_log_and_logs_key_returns_typed_error(client, auth_headers):
    response = client.post("/api/v1/ingest", json={}, headers=auth_headers)

    assert response.status_code == 422
    assert response.json() == {
        "error": "Request must contain 'log' (single) or 'logs' (batch)",
        "status_code": 422,
    }


def test_ingest_logs_not_a_list_returns_typed_error(client, auth_headers):
    response = client.post("/api/v1/ingest", json={"logs": "not-a-list"}, headers=auth_headers)

    assert response.status_code == 422
    assert response.json() == {"error": "'logs' must be a list", "status_code": 422}
