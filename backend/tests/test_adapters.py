"""
SafeSOC — Source Adapter Tests
"""

import json

from app.adapters import wazuh
from app.core.enums import LogType, Severity
from app.schemas.log import NormalizedLog

# ── Sample fixtures ──────────────────────────────────────────────

WAZUH_SSH_BRUTE_FORCE_ALERT = {
    "timestamp": "2026-08-06T02:47:11.123+0000",
    "rule": {
        "id": "5710",
        "level": 10,
        "description": "sshd: Attempt to login using a non-existent user",
        "groups": ["authentication_failed", "sshd"],
        "mitre": {
            "id": ["T1110"],
            "tactic": ["Credential Access"],
            "technique": ["Brute Force"],
        },
    },
    "agent": {"id": "001", "name": "DESKTOP-042", "ip": "192.168.1.42"},
    "decoder": {"name": "sshd"},
    "data": {"srcip": "45.33.32.156", "srcport": "48221", "dstuser": "admin"},
    "full_log": "Aug  6 02:47:11 DESKTOP-042 sshd[12345]: Invalid user admin from 45.33.32.156 port 48221",
}

# A syscheck (file integrity) alert: no MITRE mapping, no network data —
# exercises the "missing/unmappable fields degrade gracefully" path.
WAZUH_SYSCHECK_ALERT = {
    "timestamp": "2026-08-06T03:10:00.000+0000",
    "rule": {
        "id": "550",
        "level": 7,
        "description": "Integrity checksum changed.",
        "groups": ["ossec", "syscheck"],
    },
    "agent": {"id": "002", "name": "WEB-SERVER-01", "ip": "10.0.0.5"},
    "decoder": {"name": "syscheck"},
    "data": {},
    "full_log": "File '/etc/passwd' checksum changed.",
}


# ── SS-018: valid NormalizedLog production ───────────────────────

def test_ssh_brute_force_alert_produces_a_valid_normalized_log():
    result = wazuh.transform(WAZUH_SSH_BRUTE_FORCE_ALERT)
    log = NormalizedLog(tenant_id="acme-corp", source="wazuh", **result)

    assert log.log_type == LogType.AUTHENTICATION
    assert log.host_id == "DESKTOP-042"
    assert log.host_ip == "192.168.1.42"
    assert log.severity == Severity.HIGH
    assert log.rule_id == "5710"
    assert log.mitre_technique == "T1110"
    assert log.mitre_tactic == "Credential Access"
    assert log.source_ip == "45.33.32.156"
    assert log.source_port == 48221
    assert log.user == "admin"


def test_syscheck_alert_produces_a_valid_normalized_log_with_graceful_nulls():
    result = wazuh.transform(WAZUH_SYSCHECK_ALERT)
    log = NormalizedLog(tenant_id="acme-corp", source="wazuh", **result)

    assert log.log_type == LogType.FILE
    assert log.host_id == "WEB-SERVER-01"
    assert log.severity == Severity.MEDIUM
    # No MITRE data in this alert -> gracefully None, not an error.
    assert log.mitre_technique is None
    assert log.mitre_tactic is None
    assert log.source_ip is None
    assert log.source_port is None


def test_raw_log_preserves_the_original_payload_as_json():
    result = wazuh.transform(WAZUH_SSH_BRUTE_FORCE_ALERT)

    assert json.loads(result["raw_log"]) == WAZUH_SSH_BRUTE_FORCE_ALERT


# ── SS-018: degrade gracefully rather than reject ─────────────────

def test_empty_payload_still_produces_a_valid_normalized_log():
    """Even a maximally degenerate alert must still validate — never rejected."""
    result = wazuh.transform({})
    log = NormalizedLog(tenant_id="acme-corp", source="wazuh", **result)

    assert log.log_type == LogType.SYSTEM
    assert log.host_id == "unknown-host"
    assert log.host_ip == "0.0.0.0"
    assert log.severity == Severity.LOW
    assert log.rule_id is None
    assert log.mitre_technique is None


def test_unparseable_timestamp_falls_back_rather_than_failing():
    alert = {**WAZUH_SSH_BRUTE_FORCE_ALERT, "timestamp": "not-a-real-timestamp"}

    result = wazuh.transform(alert)

    # Falls back to "now" rather than passing through the garbage value,
    # so downstream NormalizedLog validation of the datetime never fails.
    log = NormalizedLog(tenant_id="acme-corp", source="wazuh", **result)
    assert log.timestamp is not None


def test_unmappable_rule_level_defaults_to_low_severity():
    alert = {**WAZUH_SSH_BRUTE_FORCE_ALERT}
    alert["rule"] = {**alert["rule"], "level": "not-a-number"}

    result = wazuh.transform(alert)

    assert result["severity"] == Severity.LOW.value
