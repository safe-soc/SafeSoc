"""
SafeSOC — NormalizedLog Schema Tests
"""

import pytest
from pydantic import ValidationError

from app.schemas.log import NormalizedLog


def _full_valid_log(base_log_fields: dict) -> dict:
    return {"tenant_id": "acme-corp", "source": "synthetic", **base_log_fields}


def test_valid_log_constructs_successfully(base_log_fields):
    log = NormalizedLog(**_full_valid_log(base_log_fields))

    assert log.tenant_id == "acme-corp"
    assert log.source == "synthetic"
    assert log.severity == "low"


def test_alert_id_is_auto_generated_when_omitted(base_log_fields):
    log = NormalizedLog(**_full_valid_log(base_log_fields))

    assert log.alert_id  # non-empty
    assert len(log.alert_id) == 36  # UUID4 string length


def test_defaults_are_applied(base_log_fields):
    log = NormalizedLog(**_full_valid_log(base_log_fields))

    assert log.user == "unknown"
    assert log.ti_enriched is False
    assert log.ti_result is None
    assert log.risk_score == 0
    assert log.anomaly_score is None
    assert log.raw_log == "{}"


@pytest.mark.parametrize(
    "missing_field",
    [
        "tenant_id",
        "source",
        "log_type",
        "timestamp",
        "host_id",
        "host_ip",
        "action",
        "description",
        "severity",
    ],
)
def test_missing_required_field_is_rejected(base_log_fields, missing_field):
    payload = _full_valid_log(base_log_fields)
    del payload[missing_field]

    with pytest.raises(ValidationError):
        NormalizedLog(**payload)


@pytest.mark.parametrize(
    "field,value",
    [
        ("source", "not-a-real-source"),
        ("log_type", "not-a-real-type"),
        ("severity", "not-a-real-severity"),
    ],
)
def test_invalid_enum_value_is_rejected(base_log_fields, field, value):
    payload = _full_valid_log(base_log_fields)
    payload[field] = value

    with pytest.raises(ValidationError):
        NormalizedLog(**payload)


def test_documented_schema_example_is_itself_valid():
    """Regression guard: the example embedded in NormalizedLog's model_config must stay valid."""
    example = NormalizedLog.model_config["json_schema_extra"]["example"]

    log = NormalizedLog(**example)

    assert log.tenant_id == "acme-corp"
    assert log.source == "wazuh"
