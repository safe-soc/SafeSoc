"""
SafeSOC — Source Adapter Tests
"""

import json

import pytest

from app.adapters import cloudlens, cloudtrail, guardduty, wazuh
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


# ── SS-019: AWS CloudTrail adapter ────────────────────────────────

CLOUDTRAIL_CONSOLE_LOGIN_EVENT = {
    "eventVersion": "1.08",
    "eventTime": "2026-08-06T02:47:11Z",
    "eventSource": "signin.amazonaws.com",
    "eventName": "ConsoleLogin",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "45.33.32.156",
    "userIdentity": {
        "type": "IAMUser",
        "arn": "arn:aws:iam::123456789012:user/alice",
        "accountId": "123456789012",
        "userName": "alice",
    },
    "resources": [],
    "eventID": "abcd1234-ef56-7890-abcd-ef1234567890",
}

CLOUDTRAIL_DENIED_S3_EVENT = {
    "eventVersion": "1.08",
    "eventTime": "2026-08-06T03:15:42Z",
    "eventSource": "s3.amazonaws.com",
    "eventName": "PutObject",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "203.0.113.9",
    "userIdentity": {
        "type": "AssumedRole",
        "arn": "arn:aws:sts::123456789012:assumed-role/dev-role/bob",
        "accountId": "123456789012",
    },
    "resources": [
        {"ARN": "arn:aws:s3:::acme-secrets-bucket", "accountId": "123456789012", "type": "AWS::S3::Object"}
    ],
    "errorCode": "AccessDenied",
    "errorMessage": "Access Denied",
    "eventID": "11112222-3333-4444-5555-666677778888",
}


def test_console_login_event_produces_a_valid_normalized_log():
    result = cloudtrail.transform(CLOUDTRAIL_CONSOLE_LOGIN_EVENT)
    log = NormalizedLog(tenant_id="acme-corp", **result)

    assert log.log_type == LogType.CLOUD
    assert log.source.value == "aws_cloudtrail"
    assert log.action == "ConsoleLogin"
    assert log.user == "alice"
    assert log.source_ip == "45.33.32.156"
    assert log.severity == Severity.LOW
    assert "ConsoleLogin" in log.description
    assert "alice" in log.description


def test_denied_event_maps_actor_ip_and_resource_into_description_and_is_high_severity():
    result = cloudtrail.transform(CLOUDTRAIL_DENIED_S3_EVENT)
    log = NormalizedLog(tenant_id="acme-corp", **result)

    assert log.log_type == LogType.CLOUD
    # No userName on an assumed-role identity -> falls back to the ARN.
    assert log.user == "arn:aws:sts::123456789012:assumed-role/dev-role/bob"
    assert log.source_ip == "203.0.113.9"
    assert log.severity == Severity.HIGH
    assert "acme-secrets-bucket" in log.description


def test_cloudtrail_raw_log_preserves_the_original_payload_as_json():
    result = cloudtrail.transform(CLOUDTRAIL_CONSOLE_LOGIN_EVENT)

    assert json.loads(result["raw_log"]) == CLOUDTRAIL_CONSOLE_LOGIN_EVENT


# ── SS-020: AWS GuardDuty adapter ─────────────────────────────────

GUARDDUTY_SSH_BRUTE_FORCE_FINDING = {
    "SchemaVersion": "2.0",
    "AccountId": "123456789012",
    "Region": "us-east-1",
    "Id": "abcd1234ef567890",
    "Type": "UnauthorizedAccess:EC2/SSHBruteForce",
    "Severity": 5.0,
    "CreatedAt": "2026-08-06T02:47:11.000Z",
    "Title": "SSH brute force attack against i-99999999.",
    "Description": "123.45.67.89 is performing SSH brute force attacks against i-99999999.",
    "Resource": {
        "ResourceType": "Instance",
        "InstanceDetails": {
            "InstanceId": "i-99999999",
            "NetworkInterfaces": [{"PrivateIpAddress": "10.0.0.1", "PublicIp": "198.51.100.1"}],
        },
    },
    "Service": {
        "Action": {
            "ActionType": "NETWORK_CONNECTION",
            "NetworkConnectionAction": {
                "RemoteIpDetails": {"IpAddressV4": "123.45.67.89"},
                "RemotePortDetails": {"Port": 51413},
                "LocalPortDetails": {"Port": 22},
            },
        }
    },
}

# An IAM-focused finding: no InstanceDetails/NetworkConnectionAction at all,
# exercising the graceful-fallback paths.
GUARDDUTY_IAM_ANOMALY_FINDING = {
    "SchemaVersion": "2.0",
    "AccountId": "123456789012",
    "Region": "us-east-1",
    "Id": "99998888ff",
    "Type": "Recon:IAMUser/MaliciousIPCaller",
    "Severity": 8.5,
    "CreatedAt": "2026-08-06T04:00:00.000Z",
    "Title": "API call to access management console from a known malicious IP.",
    "Resource": {
        "ResourceType": "AccessKey",
        "AccessKeyDetails": {"UserName": "bob", "AccessKeyId": "AKIAEXAMPLE"},
    },
}


def test_ssh_brute_force_finding_produces_a_valid_normalized_log():
    result = guardduty.transform(GUARDDUTY_SSH_BRUTE_FORCE_FINDING)
    log = NormalizedLog(tenant_id="acme-corp", **result)

    assert log.log_type == LogType.CLOUD
    assert log.source.value == "aws_guardduty"
    assert log.host_id == "i-99999999"
    assert log.host_ip == "10.0.0.1"
    assert log.action == "UnauthorizedAccess:EC2/SSHBruteForce"
    assert "SSH brute force" in log.description
    assert log.severity == Severity.MEDIUM
    assert log.source_ip == "123.45.67.89"
    assert log.source_port == 51413
    assert log.destination_port == 22
    assert log.rule_id == "abcd1234ef567890"


def test_iam_anomaly_finding_degrades_gracefully_without_instance_or_network_data():
    result = guardduty.transform(GUARDDUTY_IAM_ANOMALY_FINDING)
    log = NormalizedLog(tenant_id="acme-corp", **result)

    assert log.log_type == LogType.CLOUD
    assert log.host_id == "123456789012"  # falls back to AccountId
    assert log.host_ip == "0.0.0.0"
    assert log.user == "bob"
    assert log.severity == Severity.HIGH
    assert log.source_ip is None
    assert log.source_port is None


def test_guardduty_raw_log_preserves_the_original_payload_as_json():
    result = guardduty.transform(GUARDDUTY_SSH_BRUTE_FORCE_FINDING)

    assert json.loads(result["raw_log"]) == GUARDDUTY_SSH_BRUTE_FORCE_FINDING


@pytest.mark.parametrize(
    "score,expected",
    [
        (0.1, Severity.LOW),
        (3.9, Severity.LOW),
        (4.0, Severity.MEDIUM),   # lower boundary of MEDIUM
        (6.9, Severity.MEDIUM),
        (7.0, Severity.HIGH),     # lower boundary of HIGH
        (8.9, Severity.HIGH),     # documented GuardDuty maximum
        (8.95, Severity.CRITICAL),  # just above the documented maximum
        (0.0, Severity.LOW),
        (None, Severity.LOW),     # missing
        ("not-a-number", Severity.LOW),  # unparseable
    ],
)
def test_guardduty_severity_boundaries(score, expected):
    finding = {**GUARDDUTY_SSH_BRUTE_FORCE_FINDING, "Severity": score}

    result = guardduty.transform(finding)

    assert result["severity"] == expected.value


# ── SS-038: CloudLens adapter ─────────────────────────────────────

# Shape matches FindingSerializer exactly (cloud/AWS-IAM-backend/core/serializers.py):
# id, category, title, description, severity, affected_resource, remediation.
CLOUDLENS_PRIVILEGE_ESCALATION_FINDING = {
    "id": 42,
    "category": "Privilege Escalation",
    "title": "User has AdministratorAccess",
    "description": "IAM user 'dave' is directly attached to the AdministratorAccess managed policy.",
    "severity": "HIGH",
    "affected_resource": "user-dave",
    "remediation": "Remove the AdministratorAccess policy and apply least-privilege permissions instead.",
}

# A finding with no remediation text — exercises the graceful-degradation path.
CLOUDLENS_MISCONFIGURATION_FINDING = {
    "id": 7,
    "category": "Misconfiguration",
    "title": "S3 bucket is publicly readable",
    "description": "Bucket 'acme-backups' has a public-read ACL.",
    "severity": "CRITICAL",
    "affected_resource": "acme-backups",
    "remediation": "",
}


def test_privilege_escalation_finding_produces_a_valid_normalized_log():
    result = cloudlens.transform(CLOUDLENS_PRIVILEGE_ESCALATION_FINDING)
    log = NormalizedLog(tenant_id="acme-corp", **result)

    assert log.log_type == LogType.CLOUD
    assert log.source.value == "cloudlens"
    assert log.host_id == "user-dave"
    assert log.host_ip == "0.0.0.0"
    assert log.action == "Privilege Escalation"
    assert log.severity == Severity.HIGH
    assert log.rule_id == "42"
    assert "AdministratorAccess" in log.description


def test_remediation_text_is_preserved_on_the_normalized_record():
    """AC: remediation text must be preserved somewhere on the normalized record."""
    result = cloudlens.transform(CLOUDLENS_PRIVILEGE_ESCALATION_FINDING)

    assert "Remove the AdministratorAccess policy" in result["description"]


def test_finding_without_remediation_still_produces_a_valid_normalized_log():
    result = cloudlens.transform(CLOUDLENS_MISCONFIGURATION_FINDING)
    log = NormalizedLog(tenant_id="acme-corp", **result)

    assert log.log_type == LogType.CLOUD
    assert log.severity == Severity.CRITICAL
    assert "publicly readable" in log.description
    assert "Remediation:" not in log.description  # nothing to append


def test_cloudlens_raw_log_preserves_the_original_payload_as_json():
    result = cloudlens.transform(CLOUDLENS_PRIVILEGE_ESCALATION_FINDING)

    assert json.loads(result["raw_log"]) == CLOUDLENS_PRIVILEGE_ESCALATION_FINDING


def test_empty_finding_still_produces_a_valid_normalized_log():
    result = cloudlens.transform({})
    log = NormalizedLog(tenant_id="acme-corp", **result)

    assert log.log_type == LogType.CLOUD
    assert log.host_id == "unknown-resource"
    assert log.severity == Severity.LOW
    assert log.rule_id is None


@pytest.mark.parametrize(
    "raw_severity,expected",
    [
        ("CRITICAL", Severity.CRITICAL),
        ("HIGH", Severity.HIGH),
        ("MEDIUM", Severity.MEDIUM),
        ("LOW", Severity.LOW),
        ("critical", Severity.CRITICAL),  # lowercase input still maps correctly
        ("unknown-value", Severity.LOW),  # unmappable -> safe default
        (None, Severity.LOW),  # missing
    ],
)
def test_cloudlens_severity_mapping(raw_severity, expected):
    """AC: CRITICAL/HIGH/MEDIUM/LOW must map explicitly, not be assumed to already match."""
    finding = {**CLOUDLENS_PRIVILEGE_ESCALATION_FINDING, "severity": raw_severity}

    result = cloudlens.transform(finding)

    assert result["severity"] == expected.value
