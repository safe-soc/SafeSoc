"""
SafeSOC — Ingestion Service Tests
"""

import pytest

from app.core.config import settings
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

def test_batch_at_exactly_the_limit_is_accepted(client, base_log_fields, mock_bulk_index_logs):
    logs = [dict(base_log_fields) for _ in range(settings.INGEST_BATCH_SIZE)]

    response = client.post("/api/v1/ingest", json={"tenant_id": "acme-corp", "logs": logs})

    assert response.status_code == 200
    body = response.json()
    assert body["accepted"] == settings.INGEST_BATCH_SIZE
    assert body["rejected"] == 0
    mock_bulk_index_logs.assert_called_once()


def test_batch_one_over_the_limit_is_rejected(client, base_log_fields, mock_bulk_index_logs):
    logs = [dict(base_log_fields) for _ in range(settings.INGEST_BATCH_SIZE + 1)]

    response = client.post("/api/v1/ingest", json={"tenant_id": "acme-corp", "logs": logs})

    assert response.status_code == 422
    assert response.json() == {
        "error": (
            f"Batch size {settings.INGEST_BATCH_SIZE + 1} exceeds maximum of "
            f"{settings.INGEST_BATCH_SIZE} logs per request"
        ),
        "status_code": 422,
    }
    mock_bulk_index_logs.assert_not_called()
