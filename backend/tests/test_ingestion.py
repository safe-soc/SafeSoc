"""
SafeSOC — Ingestion Service Tests
"""

import pytest

from app.core.config import settings
from app.core.exceptions import IngestionError
from app.services.ingestion import process_ingest_batch


@pytest.mark.asyncio
async def test_all_valid_logs_are_accepted(base_log_fields, mock_bulk_index_logs):
    logs = [dict(base_log_fields), dict(base_log_fields)]

    result = await process_ingest_batch(logs=logs, tenant_id="acme-corp", source="synthetic")

    assert result["accepted"] == 2
    assert result["rejected"] == 0
    assert len(result["alert_ids"]) == 2
    assert result["errors"] is None
    mock_bulk_index_logs.assert_called_once()


@pytest.mark.asyncio
async def test_tenant_id_and_source_are_injected_when_absent(base_log_fields, mock_bulk_index_logs):
    logs = [dict(base_log_fields)]  # no tenant_id / source key present

    await process_ingest_batch(logs=logs, tenant_id="acme-corp", source="synthetic")

    written_docs = mock_bulk_index_logs.call_args.args[0]
    assert written_docs[0]["tenant_id"] == "acme-corp"
    assert written_docs[0]["source"] == "synthetic"


@pytest.mark.asyncio
async def test_partial_failure_keeps_valid_logs_in_same_batch(base_log_fields, mock_bulk_index_logs):
    valid_log = dict(base_log_fields)
    invalid_log = dict(base_log_fields)
    del invalid_log["host_id"]  # required field missing -> should fail validation

    result = await process_ingest_batch(
        logs=[valid_log, invalid_log], tenant_id="acme-corp", source="synthetic"
    )

    assert result["accepted"] == 1
    assert result["rejected"] == 1
    assert len(result["alert_ids"]) == 1
    assert result["errors"] is not None
    assert result["errors"][0]["index"] == 1
    mock_bulk_index_logs.assert_called_once()


@pytest.mark.asyncio
async def test_all_invalid_logs_are_rejected_without_a_write(base_log_fields, mock_bulk_index_logs):
    invalid_log = dict(base_log_fields)
    del invalid_log["severity"]

    result = await process_ingest_batch(
        logs=[invalid_log], tenant_id="acme-corp", source="synthetic"
    )

    assert result["accepted"] == 0
    assert result["rejected"] == 1
    assert result["alert_ids"] == []
    assert result["errors"][0]["index"] == 0
    mock_bulk_index_logs.assert_not_called()


@pytest.mark.asyncio
async def test_empty_batch_is_a_no_op(mock_bulk_index_logs):
    result = await process_ingest_batch(logs=[], tenant_id="acme-corp", source="synthetic")

    assert result == {"accepted": 0, "rejected": 0, "alert_ids": [], "errors": None}
    mock_bulk_index_logs.assert_not_called()


# ── Router-level: batch size cap (SS-005) ─────────────────────
# INGEST_BATCH_SIZE enforcement lives in routers/v1/ingest.py, so these
# go through the real endpoint rather than calling process_ingest_batch
# directly.

def test_batch_at_exactly_the_limit_is_accepted(client, base_log_fields, mock_bulk_index_logs, auth_headers):
    logs = [dict(base_log_fields) for _ in range(settings.INGEST_BATCH_SIZE)]

    response = client.post("/api/v1/ingest", json={"logs": logs}, headers=auth_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["accepted"] == settings.INGEST_BATCH_SIZE
    assert body["rejected"] == 0
    mock_bulk_index_logs.assert_called_once()


def test_batch_one_over_the_limit_is_rejected(client, base_log_fields, mock_bulk_index_logs, auth_headers):
    logs = [dict(base_log_fields) for _ in range(settings.INGEST_BATCH_SIZE + 1)]

    response = client.post("/api/v1/ingest", json={"logs": logs}, headers=auth_headers)

    assert response.status_code == 422
    assert response.json() == {
        "error": (
            f"Batch size {settings.INGEST_BATCH_SIZE + 1} exceeds maximum of "
            f"{settings.INGEST_BATCH_SIZE} logs per request"
        ),
        "status_code": 422,
    }
    mock_bulk_index_logs.assert_not_called()


# ── Adapter dispatch (SS-021) ──────────────────────────────────

@pytest.mark.asyncio
async def test_wazuh_source_routes_raw_payloads_through_the_wazuh_adapter(mock_bulk_index_logs):
    raw_wazuh_alert = {
        "timestamp": "2026-08-06T02:47:11.123+0000",
        "rule": {"id": "5710", "level": 10, "description": "sshd auth failure", "groups": ["sshd"]},
        "agent": {"name": "DESKTOP-042", "ip": "192.168.1.42"},
        "decoder": {"name": "sshd"},
        "data": {"srcip": "45.33.32.156"},
    }

    result = await process_ingest_batch(logs=[raw_wazuh_alert], tenant_id="acme-corp", source="wazuh")

    assert result["accepted"] == 1
    assert result["rejected"] == 0
    written_docs = mock_bulk_index_logs.call_args.args[0]
    assert written_docs[0]["host_id"] == "DESKTOP-042"
    assert written_docs[0]["source"] == "wazuh"
    assert written_docs[0]["tenant_id"] == "acme-corp"


@pytest.mark.asyncio
async def test_aws_cloudtrail_source_routes_raw_payloads_through_the_cloudtrail_adapter(mock_bulk_index_logs):
    raw_event = {
        "eventTime": "2026-08-06T02:47:11Z",
        "eventName": "ConsoleLogin",
        "eventSource": "signin.amazonaws.com",
        "userIdentity": {"userName": "alice", "accountId": "123456789012"},
        "sourceIPAddress": "45.33.32.156",
    }

    result = await process_ingest_batch(logs=[raw_event], tenant_id="acme-corp", source="aws_cloudtrail")

    assert result["accepted"] == 1
    written_docs = mock_bulk_index_logs.call_args.args[0]
    assert written_docs[0]["action"] == "ConsoleLogin"
    assert written_docs[0]["source"] == "aws_cloudtrail"


@pytest.mark.asyncio
async def test_aws_guardduty_source_routes_raw_payloads_through_the_guardduty_adapter(mock_bulk_index_logs):
    raw_finding = {
        "AccountId": "123456789012",
        "Id": "abcd1234",
        "Type": "UnauthorizedAccess:EC2/SSHBruteForce",
        "Severity": 5.0,
        "CreatedAt": "2026-08-06T02:47:11.000Z",
        "Title": "SSH brute force attack",
    }

    result = await process_ingest_batch(logs=[raw_finding], tenant_id="acme-corp", source="aws_guardduty")

    assert result["accepted"] == 1
    written_docs = mock_bulk_index_logs.call_args.args[0]
    assert written_docs[0]["action"] == "UnauthorizedAccess:EC2/SSHBruteForce"
    assert written_docs[0]["source"] == "aws_guardduty"


@pytest.mark.asyncio
async def test_synthetic_source_is_still_not_transformed(base_log_fields, mock_bulk_index_logs):
    """Synthetic logs are already NormalizedLog-shaped; dispatch must leave them alone."""
    result = await process_ingest_batch(logs=[dict(base_log_fields)], tenant_id="acme-corp", source="synthetic")

    assert result["accepted"] == 1


@pytest.mark.asyncio
async def test_unknown_source_raises_ingestion_error_instead_of_falling_through_to_synthetic(mock_bulk_index_logs):
    with pytest.raises(IngestionError):
        await process_ingest_batch(logs=[{"anything": "here"}], tenant_id="acme-corp", source="not-a-real-source")

    mock_bulk_index_logs.assert_not_called()


def test_router_rejects_unknown_source_with_a_clear_422(client, auth_headers):
    response = client.post(
        "/api/v1/ingest",
        json={"source": "not-a-real-source", "log": {"anything": "here"}},
        headers=auth_headers,
    )

    assert response.status_code == 422
    assert response.json() == {
        "error": "Unknown log source 'not-a-real-source' — no adapter registered for it.",
        "status_code": 422,
    }


# ── Async enrichment queuing (SS-026) ──────────────────────────

def test_ingest_queues_enrichment_for_each_accepted_alert(
    client, base_log_fields, mock_bulk_index_logs, auth_headers, _mock_enrichment_queueing
):
    response = client.post("/api/v1/ingest", json={"log": base_log_fields}, headers=auth_headers)

    assert response.status_code == 200
    alert_id = response.json()["alert_ids"][0]
    _mock_enrichment_queueing.assert_called_once_with(alert_id)


def test_ingest_succeeds_even_if_enrichment_queueing_fails(
    client, base_log_fields, mock_bulk_index_logs, auth_headers, _mock_enrichment_queueing
):
    _mock_enrichment_queueing.side_effect = ConnectionError("broker unreachable")

    response = client.post("/api/v1/ingest", json={"log": base_log_fields}, headers=auth_headers)

    assert response.status_code == 200  # ingestion succeeds regardless of queueing outcome
    assert response.json()["accepted"] == 1
