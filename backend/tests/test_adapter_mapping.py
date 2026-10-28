"""
SafeSOC — Adapter Semantic Mapping Tests
Every simulator sample (injector/sim/samples.py: real Wazuh/CloudTrail/
GuardDuty payload shapes) through its real adapter must produce the
canonical log_type/action the correlation detectors key on, plus the
user, network, process and file fields that payload carries. Also the
mapping's edge cases (adapters/mapping.py) and the CloudTrail/GuardDuty
field fixes. Imports injector.sim with the repo root on sys.path, like
test_sim_foundation.py.
"""

import copy
import hashlib
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from injector.sim.org import load_org  # noqa: E402
from injector.sim.samples import sample_builders  # noqa: E402

import app.adapters  # noqa: E402,F401  (registers the built-in adapters)
from app.adapters import cloudtrail, guardduty, wazuh  # noqa: E402
from app.adapters.mapping import parse_sha256  # noqa: E402
from app.adapters.sdk import registry  # noqa: E402
from app.core.enums import EventAction  # noqa: E402
from app.schemas.log import NormalizedLog  # noqa: E402

TS = datetime(2026, 10, 27, 10, 15, 30, tzinfo=timezone.utc)
WORD = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"


def _sha256(seed: str) -> str:
    """The SHA256 samples._hashes() puts in a Sysmon hashes string for `seed`."""
    return hashlib.sha256(seed.lower().encode()).hexdigest()


def _expect(log_type: str, action: str, user: str, source_ip: Optional[str] = None, **extra: Any) -> dict[str, Any]:
    return {"log_type": log_type, "action": action, "user": user, "source_ip": source_ip, **extra}


# Builder name -> the fields its sample must normalize to. A key not
# listed here is not asserted; source_ip is always asserted (None = none).
EXPECTED: dict[str, dict[str, Any]] = {
    "windows.logon_success": _expect("authentication", "login_success", "neha.sharma"),
    "windows.logon_failure": _expect("authentication", "failed_login", "administrator", "10.8.0.14", source_port=52113),
    "windows.special_privileges": _expect("privilege", "privilege_assigned", "adm.rahul"),
    "windows.process_created": _expect(
        "process", "process_start", "neha.sharma", process_name="powershell.exe", parent_process="explorer.exe",
        command_line="powershell.exe -NoProfile -Command Get-Date",
    ),
    "windows.user_created": _expect("privilege", "account_created", "intern.tmp"),
    "windows.member_added_global_group": _expect(
        "privilege", "group_member_added", "adm.rahul",
        description="Domain Admins Group Changed (member: CN=Sneha Kulkarni,CN=Users,DC=emberbay,DC=local, group: Domain Admins)",
    ),
    "windows.member_added_local_group": _expect(
        "privilege", "group_member_added", "adm.rahul",
        description="Administrators Group Changed (member: CN=Neha Sharma,CN=Users,DC=emberbay,DC=local, group: Administrators)",
    ),
    "windows.audit_log_cleared": _expect("system", "audit_log_cleared", "adm.rahul"),
    "windows.usb_device_recognized": _expect("system", "usb_device_connected", "EB-FIN-WS07$"),
    "windows.sysmon_process_create": _expect(
        "process", "process_start", "neha.sharma", process_name="WINWORD.EXE", parent_process="explorer.exe",
        command_line=f'"{WORD}" /n "C:\\Users\\neha.sharma\\Documents\\Budget.docx"', file_hash=_sha256(WORD),
    ),
    "windows.sysmon_network_connect": _expect(
        "network", "outbound_connection", "neha.sharma", "10.10.10.23", destination_ip="10.10.30.10",
        destination_port=443, protocol="tcp", process_name="chrome.exe",
    ),
    "windows.sysmon_file_create": _expect(
        "file", "file_create", "neha.sharma", process_name="WINWORD.EXE",
        file_path=r"C:\Users\neha.sharma\Documents\Budget-Q3.docx", file_hash=None,
    ),
    "windows.sysmon_file_delete": _expect(
        "file", "file_delete", "neha.sharma", process_name="explorer.exe",
        file_path=r"C:\Users\neha.sharma\Downloads\old-notes.txt", file_hash=_sha256("old-notes.txt"),
    ),
    "linux.ssh_failed_password": _expect("authentication", "failed_login", "svc-webapp", "45.148.10.121", source_port=44512),
    "linux.ssh_invalid_user": _expect("authentication", "failed_login", "admin", "45.148.10.121"),
    "linux.ssh_accepted_password": _expect("authentication", "login_success", "karthik.reddy", "10.8.0.6"),
    "linux.sudo_command": _expect("privilege", "privilege_assigned", "karthik.reddy", command_line="/usr/bin/apt-get update"),
    # data.protocol is the HTTP method here (Wazuh's web-accesslog decoder) — not a transport protocol.
    "web.access_log": _expect("network", "web_attack", "unknown", "45.148.10.121", protocol=None),
    "vpn.auth_failed": _expect("authentication", "failed_login", "unknown", "2.57.121.25"),
    "vpn.peer_connection_initiated": _expect("authentication", "login_success", "neha.sharma", "198.51.100.23"),
    # No mapping for rule 100401: the decoder-name fallback.
    "vpn.client_address_assigned": _expect("system", "openvpn", "neha.sharma", "198.51.100.23"),
    "vpn.client_disconnected": _expect("authentication", "logout", "neha.sharma", "198.51.100.23"),
    "firewall.filterlog": _expect(
        "network", "connection_blocked", "unknown", "2.57.121.25", destination_ip="203.0.113.10",
        destination_port=3389, protocol="tcp",
    ),
    "firewall.suricata_alert": _expect(
        "network", "ids_alert", "unknown", "45.148.10.121", source_port=44512, destination_ip="10.10.30.10",
        destination_port=80, protocol="tcp",
    ),
    "mail.attachment_warning": _expect("system", "email_received", "unknown", "140.246.61.93"),
    "mail.content_filter_verdict": _expect("system", "email_received", "unknown", "140.246.61.93"),
    "database.connection_authorized": _expect("authentication", "login_success", "svc-sql", "10.10.30.10"),
    "database.password_authentication_failed": _expect("authentication", "failed_login", "postgres", "10.10.10.41"),
    "database.copy_to_stdout": _expect("network", "db_export", "svc-sql", "10.10.30.10"),
    "cloudtrail.get_caller_identity": _expect("cloud", "GetCallerIdentity", "svc-web-deploy", "203.0.113.20"),
    "cloudtrail.list_buckets": _expect("cloud", "ListBuckets", "svc-web-deploy", "203.0.113.20"),
    "cloudtrail.get_object": _expect("cloud", "GetObject", "svc-web-deploy", "203.0.113.20"),
    "cloudtrail.console_login": _expect("authentication", "login_success", "adm.rahul", "203.0.113.10"),
    "guardduty.finding": _expect("cloud", "Recon:IAMUser/MaliciousIPCaller", "svc-web-deploy", "93.174.95.106"),
    "guardduty.instance_credential_exfiltration_outside_aws": _expect(
        "cloud", "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS", "i-0abc123def4567890",
        "93.174.95.106",
    ),
}

# Builders whose eventdata carries a process ID the adapter must parse (hex for 4688, decimal for Sysmon).
_PROCESS_ID_FIELD = {
    "windows.process_created": "newProcessId",
    "windows.sysmon_process_create": "processId",
    "windows.sysmon_network_connect": "processId",
    "windows.sysmon_file_create": "processId",
    "windows.sysmon_file_delete": "processId",
}


def _samples() -> dict[str, tuple[str, dict]]:
    return {name: (source, make(TS, None)) for name, source, make in sample_builders(load_org())}


def _ingest_like(source: str, payload: dict) -> NormalizedLog:
    log = registry.get(source)(copy.deepcopy(payload))
    log["tenant_id"] = str(uuid.uuid4())
    log.setdefault("source", source)
    return NormalizedLog(**log)


def test_expectations_cover_every_sample():
    assert set(EXPECTED) == set(_samples())


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_sample_maps_to_canonical_fields(name):
    source, payload = _samples()[name]
    log = _ingest_like(source, payload)

    actual = log.model_dump(mode="json")
    for field, expected in EXPECTED[name].items():
        assert actual[field] == expected, f"{name}.{field}"

    if name in _PROCESS_ID_FIELD:
        raw_pid = payload["data"]["win"]["eventdata"][_PROCESS_ID_FIELD[name]]
        assert log.process_id == int(raw_pid, 16 if raw_pid.startswith("0x") else 10)


def test_canonical_actions_match_the_strings_detectors_key_on():
    assert EventAction.FAILED_LOGIN == "failed_login"
    assert EventAction.LOGIN_SUCCESS == "login_success"
    assert EventAction.OUTBOUND_CONNECTION == "outbound_connection"


# ── Windows edge cases ──────────────────────────────────────────

def _windows_alert(event_id: str, eventdata: dict, *, channel: str = "Security", groups=("windows",)) -> dict:
    return {
        "timestamp": "2026-10-27T10:15:30.000+0000",
        "rule": {"id": "60122", "level": 5, "description": "Windows event", "groups": list(groups)},
        "agent": {"id": "001", "name": "EB-FS01", "ip": "10.10.20.20"},
        "decoder": {"name": "windows_eventchannel"},
        "data": {"win": {"system": {"eventID": event_id, "channel": channel}, "eventdata": eventdata}},
    }


@pytest.mark.parametrize("ip", ["-", "::1", "127.0.0.1", ""])
def test_windows_logon_failure_ignores_placeholder_and_loopback_ips(ip):
    result = wazuh.transform(_windows_alert("4625", {"targetUserName": "administrator", "ipAddress": ip, "ipPort": "0"}))

    assert result["action"] == "failed_login"
    assert result.get("source_ip") is None
    assert result.get("source_port") is None


def test_windows_placeholder_user_degrades_to_unknown():
    result = wazuh.transform(_windows_alert("4625", {"targetUserName": "-"}))
    assert result["user"] == "unknown"


def test_windows_eventdata_keys_are_matched_case_insensitively():
    result = wazuh.transform(_windows_alert("4624", {"TargetUserName": "neha.sharma", "IpAddress": "10.8.0.6"}))
    assert (result["user"], result["source_ip"]) == ("neha.sharma", "10.8.0.6")


def test_sysmon_user_has_its_domain_prefix_stripped():
    alert = _windows_alert(
        "11", {"user": "EMBERBAY\\neha.sharma", "image": "C:\\x.exe", "targetFilename": "C:\\a.txt"},
        channel="Microsoft-Windows-Sysmon/Operational",
    )
    assert wazuh.transform(alert)["user"] == "neha.sharma"


def test_sysmon_inbound_network_connection():
    alert = _windows_alert(
        "3", {"initiated": "false", "sourceIp": "10.10.10.50", "destinationIp": "10.10.10.23", "destinationPort": "445"},
        channel="Microsoft-Windows-Sysmon/Operational",
    )
    result = wazuh.transform(alert)
    assert (result["log_type"], result["action"]) == ("network", "inbound_connection")
    assert (result["source_ip"], result["destination_ip"], result["destination_port"]) == ("10.10.10.50", "10.10.10.23", 445)


def test_hex_process_id_is_parsed():
    alert = _windows_alert("4688", {"subjectUserName": "neha.sharma", "newProcessId": "0x1f2c", "processId": "0x1012",
                                    "newProcessName": "C:\\Windows\\System32\\cmd.exe"})
    result = wazuh.transform(alert)
    assert result["process_id"] == 0x1F2C
    assert result["process_name"] == "cmd.exe"


@pytest.mark.parametrize("hashes, expected", [
    ("SHA1=AA,MD5=BB,SHA256=ABCDEF0123,IMPHASH=CC", "abcdef0123"),
    ("sha256=abc", "abc"),
    ("SHA1=AA,MD5=BB", None),
    ("", None),
    (None, None),
])
def test_sysmon_hashes_parsing(hashes, expected):
    assert parse_sha256(hashes) == expected


def test_unmapped_windows_event_falls_through_to_rule_groups_then_fallback():
    unmapped = wazuh.transform(_windows_alert("4999", {}))
    assert unmapped["action"] == "windows_eventchannel"

    by_group = wazuh.transform(_windows_alert("4999", {}, groups=("windows", "authentication_failed")))
    assert by_group["action"] == "failed_login"


# ── Rule-group edge cases ───────────────────────────────────────

def _sudo_alert(dstuser: str) -> dict:
    return {
        "rule": {"id": "5402", "level": 3, "description": "Successful sudo executed.", "groups": ["syslog", "sudo"]},
        "agent": {"name": "EB-DEV-LX01", "ip": "10.10.40.21"},
        "decoder": {"parent": "sudo", "name": "sudo"},
        "data": {"srcuser": "karthik.reddy", "dstuser": dstuser, "command": "/usr/bin/id"},
    }


def test_sudo_to_root_is_a_privilege_assignment_by_the_invoking_user():
    result = wazuh.transform(_sudo_alert("root"))
    assert (result["log_type"], result["action"], result["user"]) == ("privilege", "privilege_assigned", "karthik.reddy")


def test_sudo_to_a_non_root_user_is_a_process_start():
    result = wazuh.transform(_sudo_alert("postgres"))
    assert (result["log_type"], result["action"], result["user"]) == ("process", "process_start", "karthik.reddy")


@pytest.mark.parametrize("data, expected", [
    ({"srcip": "10.10.10.23", "dstip": "142.250.183.14"}, "outbound_connection"),
    ({"srcip": "2.57.121.25", "dstip": "203.0.113.10"}, "inbound_connection"),
    ({"srcip": "2.57.121.25", "dstip": "10.10.30.10", "direction": "out"}, "outbound_connection"),
])
def test_firewall_pass_direction(data, expected):
    alert = {
        "rule": {"id": "100700", "level": 3, "description": "pfSense firewall pass event.", "groups": ["pfsense", "firewall_pass"]},
        "decoder": {"name": "pf"},
        "data": data,
    }
    result = wazuh.transform(alert)
    assert (result["log_type"], result["action"]) == ("network", expected)


@pytest.mark.parametrize("groups, expected", [
    (["web", "accesslog"], "web_request"),
    (["web", "accesslog", "attack"], "web_attack"),
    (["web", "accesslog", "web_scan"], "web_attack"),
])
def test_web_access_log_attack_vs_request(groups, expected):
    alert = {"rule": {"id": "31100", "level": 3, "groups": groups}, "decoder": {"name": "web-accesslog"}, "data": {}}
    assert wazuh.transform(alert)["action"] == expected


@pytest.mark.parametrize("event, expected", [("added", "file_create"), ("modified", "file_modify"), ("deleted", "file_delete")])
def test_syscheck_events(event, expected):
    alert = {
        "rule": {"id": "550", "level": 7, "groups": ["ossec", "syscheck", f"syscheck_entry_{event}"]},
        "decoder": {"name": "syscheck_integrity_changed"},
        "syscheck": {"path": "/etc/passwd", "event": event, "sha256_after": "ab12"},
    }
    result = wazuh.transform(alert)
    assert (result["log_type"], result["action"], result["file_path"]) == ("file", expected, "/etc/passwd")
    assert result["file_hash"] == "ab12"


def test_unknown_decoder_still_ingests_with_the_decoder_name_as_action():
    alert = {
        "rule": {"id": "99999", "level": 4, "description": "Something new", "groups": ["custom_thing"]},
        "agent": {"name": "EB-APP01", "ip": "10.10.30.40"},
        "decoder": {"name": "my_custom_decoder"},
        "data": {"srcip": "10.10.30.41"},
    }
    log = NormalizedLog(tenant_id="t", source="wazuh", **wazuh.transform(alert))

    assert log.action == "my_custom_decoder"
    assert log.log_type.value == "system"
    assert log.source_ip == "10.10.30.41"


def test_severity_comes_from_the_rule_level_not_the_mapping():
    alert = _sudo_alert("root")
    alert["rule"]["level"] = 12
    assert wazuh.transform(alert)["severity"] == "critical"


# ── CloudTrail / GuardDuty ──────────────────────────────────────

def _console_login(result: Optional[str], identity: dict) -> dict:
    return {
        "eventTime": "2026-10-27T10:15:30Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "sourceIPAddress": "45.33.32.156",
        "userIdentity": {"accountId": "111122223333", **identity},
        "responseElements": {"ConsoleLogin": result} if result else None,
    }


def test_cloudtrail_console_login_success():
    result = cloudtrail.transform(_console_login("Success", {"type": "IAMUser", "userName": "alice"}))
    assert (result["log_type"], result["action"], result["user"]) == ("authentication", "login_success", "alice")
    assert result["source_ip"] == "45.33.32.156"


def test_cloudtrail_console_login_failure_takes_the_user_from_the_arn():
    identity = {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/ops/bob"}
    result = cloudtrail.transform(_console_login("Failure", identity))
    assert (result["log_type"], result["action"], result["user"]) == ("authentication", "failed_login", "bob")
    assert "ConsoleLogin" in result["description"]


def test_cloudtrail_console_login_without_a_result_keeps_the_event_name():
    result = cloudtrail.transform(_console_login(None, {"type": "Root", "arn": "arn:aws:iam::111122223333:root"}))
    assert (result["log_type"], result["action"], result["user"]) == ("authentication", "ConsoleLogin", "Root")


def test_guardduty_api_call_finding_maps_remote_ip_and_user():
    finding = {
        "Id": "f1", "AccountId": "111122223333", "Type": "Recon:IAMUser/MaliciousIPCaller", "Severity": 5.0,
        "CreatedAt": "2026-10-27T10:15:30.000Z",
        "Resource": {"AccessKeyDetails": {"UserName": "svc-web-deploy"}},
        "Service": {"Action": {"AwsApiCallAction": {"RemoteIpDetails": {"IpAddressV4": "93.174.95.106"}}}},
    }
    result = guardduty.transform(finding)
    assert (result["source_ip"], result["user"]) == ("93.174.95.106", "svc-web-deploy")
    assert (result["log_type"], result["action"]) == ("cloud", "Recon:IAMUser/MaliciousIPCaller")
