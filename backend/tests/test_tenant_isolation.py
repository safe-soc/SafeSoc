"""
SafeSOC — Tenant Isolation Tests (SS-016)
Proves tenant A's JWT cannot be used to read or write tenant B's data
via POST /api/v1/ingest or GET /api/v1/alerts.
"""

import uuid
from unittest.mock import AsyncMock

import pytest


# ── POST /api/v1/ingest ─────────────────────────────────────────

def test_ingest_requires_authentication(client, base_log_fields):
    response = client.post("/api/v1/ingest", json={"log": base_log_fields})

    assert response.status_code == 401


def test_ingest_writes_under_the_authenticated_tenant_not_a_caller_supplied_one(
    client, base_log_fields, mock_bulk_index_logs, make_auth_headers
):
    tenant_a = uuid.uuid4()
    tenant_b = uuid.uuid4()
    headers = make_auth_headers(tenant_id=tenant_a)

    # Attempt to smuggle tenant B via the individual log object itself.
    malicious_log = dict(base_log_fields)
    malicious_log["tenant_id"] = str(tenant_b)

    response = client.post("/api/v1/ingest", json={"log": malicious_log}, headers=headers)

    assert response.status_code == 200
    written_docs = mock_bulk_index_logs.call_args.args[0]
    assert written_docs[0]["tenant_id"] == str(tenant_a)
    assert written_docs[0]["tenant_id"] != str(tenant_b)


def test_ingest_rejects_mismatched_top_level_tenant_id(client, base_log_fields, make_auth_headers):
    tenant_a = uuid.uuid4()
    tenant_b = uuid.uuid4()
    headers = make_auth_headers(tenant_id=tenant_a)

    response = client.post(
        "/api/v1/ingest",
        json={"tenant_id": str(tenant_b), "log": base_log_fields},
        headers=headers,
    )

    assert response.status_code == 403


def test_ingest_accepts_top_level_tenant_id_matching_the_token(
    client, base_log_fields, mock_bulk_index_logs, make_auth_headers
):
    tenant_a = uuid.uuid4()
    headers = make_auth_headers(tenant_id=tenant_a)

    response = client.post(
        "/api/v1/ingest",
        json={"tenant_id": str(tenant_a), "log": base_log_fields},
        headers=headers,
    )

    assert response.status_code == 200


# ── GET /api/v1/alerts ──────────────────────────────────────────

def test_alerts_requires_authentication(client):
    response = client.get("/api/v1/alerts")

    assert response.status_code == 401


def test_alerts_searches_only_the_authenticated_tenant(client, make_auth_headers, monkeypatch):
    tenant_a = uuid.uuid4()
    headers = make_auth_headers(tenant_id=tenant_a)
    mock_search = AsyncMock(return_value={"total": 0, "page": 1, "size": 50, "pages": 0, "alerts": []})
    monkeypatch.setattr("app.routers.v1.alerts.search_alerts", mock_search)

    response = client.get("/api/v1/alerts", headers=headers)

    assert response.status_code == 200
    mock_search.assert_called_once()
    assert mock_search.call_args.kwargs["tenant_id"] == str(tenant_a)


def test_alerts_rejects_request_for_a_different_tenant_id(client, make_auth_headers, monkeypatch):
    tenant_a = uuid.uuid4()
    tenant_b = uuid.uuid4()
    headers = make_auth_headers(tenant_id=tenant_a)
    mock_search = AsyncMock()
    monkeypatch.setattr("app.routers.v1.alerts.search_alerts", mock_search)

    # Tenant A's token tries to read tenant B's alerts by naming it explicitly.
    response = client.get(f"/api/v1/alerts?tenant_id={tenant_b}", headers=headers)

    assert response.status_code == 403
    mock_search.assert_not_called()


def test_alerts_accepts_tenant_id_matching_the_token(client, make_auth_headers, monkeypatch):
    tenant_a = uuid.uuid4()
    headers = make_auth_headers(tenant_id=tenant_a)
    mock_search = AsyncMock(return_value={"total": 0, "page": 1, "size": 50, "pages": 0, "alerts": []})
    monkeypatch.setattr("app.routers.v1.alerts.search_alerts", mock_search)

    response = client.get(f"/api/v1/alerts?tenant_id={tenant_a}", headers=headers)

    assert response.status_code == 200
