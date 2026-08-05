"""
SafeSOC — Ingestion Service Tests
"""

import pytest

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
