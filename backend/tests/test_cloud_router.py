"""
SafeSOC — Cloud Findings Bridge Router Tests
"""

import uuid
from unittest.mock import AsyncMock

import pytest

from app.core.config import settings

CLOUDLENS_FINDING = {
    "id": 42,
    "category": "Privilege Escalation",
    "title": "User has AdministratorAccess",
    "description": "IAM user 'dave' is directly attached to the AdministratorAccess managed policy.",
    "severity": "HIGH",
    "affected_resource": "user-dave",
    "remediation": "Remove the AdministratorAccess policy and apply least-privilege permissions instead.",
}


@pytest.fixture
def service_token(monkeypatch) -> str:
    """A configured CLOUDLENS_SERVICE_TOKEN, so the endpoint isn't closed-by-default for these tests."""
    monkeypatch.setattr(settings, "CLOUDLENS_SERVICE_TOKEN", "test-shared-secret")
    return "test-shared-secret"


def test_rejects_request_with_no_service_token(client, mock_bulk_index_logs, service_token):
    response = client.post(
        "/api/v1/cloud/findings", json={"tenant_id": "acme-corp", "findings": [CLOUDLENS_FINDING]}
    )

    assert response.status_code == 401


def test_rejects_request_with_the_wrong_service_token(client, mock_bulk_index_logs, service_token):
    response = client.post(
        "/api/v1/cloud/findings",
        json={"tenant_id": "acme-corp", "findings": [CLOUDLENS_FINDING]},
        headers={"X-Service-Token": "not-the-real-token"},
    )

    assert response.status_code == 401


def test_rejects_every_request_when_no_service_token_is_configured(client, mock_bulk_index_logs, monkeypatch):
    """Closed by default: an unconfigured token must never mean 'auth disabled.'"""
    monkeypatch.setattr(settings, "CLOUDLENS_SERVICE_TOKEN", "")

    response = client.post(
        "/api/v1/cloud/findings",
        json={"tenant_id": "acme-corp", "findings": [CLOUDLENS_FINDING]},
        headers={"X-Service-Token": "anything"},
    )

    assert response.status_code == 401


def test_accepts_findings_with_the_correct_service_token(client, mock_bulk_index_logs, service_token):
    response = client.post(
        "/api/v1/cloud/findings",
        json={"tenant_id": "acme-corp", "findings": [CLOUDLENS_FINDING]},
        headers={"X-Service-Token": service_token},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["accepted"] == 1
    assert body["rejected"] == 0
    assert len(body["alert_ids"]) == 1


def test_findings_are_transformed_via_the_cloudlens_adapter(client, mock_bulk_index_logs, service_token):
    """Confirms the SS-038 adapter is genuinely wired in, not just the raw payload being passed through."""
    client.post(
        "/api/v1/cloud/findings",
        json={"tenant_id": "acme-corp", "findings": [CLOUDLENS_FINDING]},
        headers={"X-Service-Token": service_token},
    )

    written_logs = mock_bulk_index_logs.call_args.args[0]
    assert len(written_logs) == 1
    log = written_logs[0]
    assert log["source"] == "cloudlens"
    assert log["log_type"] == "cloud"
    assert log["host_id"] == "user-dave"
    assert log["severity"] == "high"  # CloudLens's "HIGH" mapped to SafeSOC's lowercase enum
    assert "Remove the AdministratorAccess policy" in log["description"]


def test_requires_tenant_id(client, mock_bulk_index_logs, service_token):
    response = client.post(
        "/api/v1/cloud/findings", json={"findings": [CLOUDLENS_FINDING]}, headers={"X-Service-Token": service_token}
    )

    assert response.status_code == 422


def test_requires_findings_to_be_a_list(client, mock_bulk_index_logs, service_token):
    response = client.post(
        "/api/v1/cloud/findings",
        json={"tenant_id": "acme-corp", "findings": "not-a-list"},
        headers={"X-Service-Token": service_token},
    )

    assert response.status_code == 422


def test_partial_success_when_one_finding_is_invalid(client, mock_bulk_index_logs, service_token):
    invalid_finding = {"category": "Misconfiguration"}  # missing everything transform() can't default around
    response = client.post(
        "/api/v1/cloud/findings",
        json={"tenant_id": "acme-corp", "findings": [CLOUDLENS_FINDING, invalid_finding]},
        headers={"X-Service-Token": service_token},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["accepted"] == 2  # the adapter degrades gracefully rather than rejecting either


def test_queues_enrichment_and_correlation_for_accepted_alerts(
    client, mock_bulk_index_logs, service_token, _mock_enrichment_queueing, _mock_correlation_queueing
):
    response = client.post(
        "/api/v1/cloud/findings",
        json={"tenant_id": "acme-corp", "findings": [CLOUDLENS_FINDING]},
        headers={"X-Service-Token": service_token},
    )

    alert_id = response.json()["alert_ids"][0]
    _mock_enrichment_queueing.assert_called_once_with(alert_id)
    _mock_correlation_queueing.assert_called_once_with(alert_id)


# ── SS-040: GET /api/v1/cloud/summary ──────────────────────────


def test_summary_requires_authentication(client):
    response = client.get("/api/v1/cloud/summary")

    assert response.status_code == 401


def test_summary_returns_the_aggregate_stats_for_the_authenticated_tenant(client, make_auth_headers, monkeypatch):
    tenant_id = uuid.uuid4()
    headers = make_auth_headers(tenant_id=tenant_id)
    fake_summary = {
        "total": 3,
        "by_severity": {"critical": 1, "high": 2},
        "by_category": {"Privilege Escalation": 3},
        "distinct_affected_resources": 2,
    }
    mock_get_summary = AsyncMock(return_value=fake_summary)
    monkeypatch.setattr("app.routers.v1.cloud.get_cloud_summary", mock_get_summary)

    response = client.get("/api/v1/cloud/summary", headers=headers)

    assert response.status_code == 200
    assert response.json() == fake_summary
    mock_get_summary.assert_called_once_with(str(tenant_id), 24)


def test_summary_accepts_a_custom_timerange(client, make_auth_headers, monkeypatch):
    headers = make_auth_headers()
    mock_get_summary = AsyncMock(
        return_value={"total": 0, "by_severity": {}, "by_category": {}, "distinct_affected_resources": 0}
    )
    monkeypatch.setattr("app.routers.v1.cloud.get_cloud_summary", mock_get_summary)

    response = client.get("/api/v1/cloud/summary?timerange_hours=168", headers=headers)

    assert response.status_code == 200
    assert mock_get_summary.call_args.args[1] == 168
