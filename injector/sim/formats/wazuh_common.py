"""
SafeSOC — Simulator Wazuh Alert Envelope
Builds Wazuh 4.x alert JSON (the shape the manager writes to
alerts.json) around source-specific `data` and `full_log`, plus the
rule catalogue every on-prem builder draws from.

Rule IDs: a rule with `stock_file` set was checked against the public
wazuh/wazuh ruleset (v4.9.2, ruleset/rules/<stock_file>): its ID,
level, description, groups and MITRE IDs are copied from there. Rules
with stock_file=None are custom (IDs 100000-100999, Wazuh's range for
local rules) and documented as such in docs/simulator.md.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional
from zoneinfo import ZoneInfo

from injector.sim.org import Asset, Org

RULESET_VERSION = "v4.9.2"

# MITRE ATT&CK names for the technique IDs the rules below carry, as a
# Wazuh alert spells them out (rule.mitre.technique / rule.mitre.tactic).
MITRE: dict[str, tuple[str, tuple[str, ...]]] = {
    "T1005": ("Data from Local System", ("Collection",)),
    "T1021": ("Remote Services", ("Lateral Movement",)),
    "T1021.004": ("SSH", ("Lateral Movement",)),
    "T1059.001": ("PowerShell", ("Execution",)),
    "T1070.004": ("File Deletion", ("Defense Evasion",)),
    "T1078": ("Valid Accounts", ("Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access")),
    "T1092": ("Communication Through Removable Media", ("Command and Control",)),
    "T1098": ("Account Manipulation", ("Persistence", "Privilege Escalation")),
    "T1110": ("Brute Force", ("Credential Access",)),
    "T1110.001": ("Password Guessing", ("Credential Access",)),
    "T1190": ("Exploit Public-Facing Application", ("Initial Access",)),
    "T1484": ("Domain Policy Modification", ("Defense Evasion", "Privilege Escalation")),
    "T1531": ("Account Access Removal", ("Impact",)),
    "T1548.003": ("Sudo and Sudo Caching", ("Privilege Escalation", "Defense Evasion")),
}


@dataclass(frozen=True)
class Rule:
    id: int
    level: int
    description: str
    groups: tuple[str, ...]
    mitre: tuple[str, ...] = ()
    stock_file: Optional[str] = None  # None = custom rule

    @property
    def custom(self) -> bool:
        return self.stock_file is None


def _stock(rule_id, level, description, groups, mitre=(), *, file):
    return Rule(rule_id, level, description, tuple(groups), tuple(mitre), file)


def _custom(rule_id, level, description, groups, mitre=()):
    return Rule(rule_id, level, description, tuple(groups), tuple(mitre), None)


_WIN = ("windows", "windows_security")
_SYSMON = ("windows", "sysmon")

# Every rule the builders can emit, keyed by a short name. groups =
# the enclosing <group name> of the stock file + the rule's own groups
# (compliance tags such as pci_dss_* are not repeated here).
RULES: dict[str, Rule] = {
    # Windows Security (0580-win-security_rules.xml)
    "win_logon_success": _stock(60106, 3, "Windows Logon Success", (*_WIN, "authentication_success"), ("T1078",), file="0580-win-security_rules.xml"),
    "win_workstation_logon_success": _stock(60118, 3, "Windows Workstation Logon Success", (*_WIN, "authentication_success"), ("T1078",), file="0580-win-security_rules.xml"),
    "win_logon_failure": _stock(60122, 5, "Logon Failure - Unknown user or bad password", (*_WIN, "authentication_failed"), ("T1531",), file="0580-win-security_rules.xml"),
    "win_user_created": _stock(60109, 8, "User account enabled or created", (*_WIN, "adduser", "account_changed"), ("T1098",), file="0580-win-security_rules.xml"),
    "win_global_group_member_added": _stock(60141, 5, "Security Enabled Global Group Member Added", (*_WIN, "group_changed", "win_group_changed"), ("T1484",), file="0580-win-security_rules.xml"),
    "win_domain_admins_changed": _stock(60159, 12, "Domain Admins Group Changed", (*_WIN, "group_changed", "win_group_changed"), ("T1484",), file="0580-win-security_rules.xml"),
    "win_domain_users_changed": _stock(60160, 5, "Domain Users Group Changed", (*_WIN, "group_changed", "win_group_changed"), ("T1484",), file="0580-win-security_rules.xml"),
    "win_local_group_member_added": _stock(60144, 5, "Security Enabled Local Group Member Added", (*_WIN, "group_changed", "win_group_changed"), ("T1484",), file="0580-win-security_rules.xml"),
    "win_administrators_changed": _stock(60154, 12, "Administrators Group Changed", (*_WIN, "group_changed", "win_group_changed"), ("T1484",), file="0580-win-security_rules.xml"),
    "win_users_group_changed": _stock(60170, 5, "Users Group Changed", (*_WIN, "group_changed", "win_group_changed"), ("T1484",), file="0580-win-security_rules.xml"),
    "win_rdp_users_changed": _stock(60179, 10, "Remote Desktop Users Group Changed", (*_WIN, "group_changed", "win_group_changed"), ("T1484",), file="0580-win-security_rules.xml"),
    "win_audit_log_cleared": _stock(60117, 9, "Windows audit log was cleared", (*_WIN, "logs_cleared"), ("T1070.004",), file="0580-win-security_rules.xml"),
    "win_usb_device": _stock(60227, 8, "A new external device was recognized by the system", _WIN, ("T1092",), file="0580-win-security_rules.xml"),
    # Windows, custom: the stock ruleset has no alerting rule for these event IDs.
    "win_special_privileges": _custom(100100, 3, "Windows: Special privileges assigned to new logon", (*_WIN, "privilege_use")),
    "win_process_created": _custom(100101, 3, "Windows: A new process has been created", (*_WIN, "process_creation")),
    # Sysmon, custom: the stock base rules for events 1/3/11/23 (61603, 61605, 61613, 61651) are level 0 and never alert.
    "sysmon_process_create": _custom(100110, 3, "Sysmon - Event 1: Process creation", (*_SYSMON, "sysmon_event1")),
    "sysmon_network_connect": _custom(100111, 3, "Sysmon - Event 3: Network connection", (*_SYSMON, "sysmon_event3")),
    "sysmon_file_create": _custom(100112, 3, "Sysmon - Event 11: File created", (*_SYSMON, "sysmon_event_11")),
    "sysmon_file_delete": _custom(100113, 3, "Sysmon - Event 23: File deleted and archived", (*_SYSMON, "sysmon_event_23")),
    # Linux (0095-sshd_rules.xml, 0020-syslog_rules.xml)
    "sshd_auth_failed": _stock(5716, 5, "sshd: authentication failed.", ("syslog", "sshd", "authentication_failed"), ("T1110",), file="0095-sshd_rules.xml"),
    "sshd_invalid_user": _stock(5710, 5, "sshd: Attempt to login using a non-existent user", ("syslog", "sshd", "authentication_failed", "invalid_login"), ("T1110.001", "T1021.004"), file="0095-sshd_rules.xml"),
    "sshd_auth_success": _stock(5715, 3, "sshd: authentication success.", ("syslog", "sshd", "authentication_success"), ("T1078", "T1021"), file="0095-sshd_rules.xml"),
    "sudo_to_root": _stock(5402, 3, "Successful sudo to ROOT executed.", ("syslog", "sudo"), ("T1548.003",), file="0020-syslog_rules.xml"),
    "sudo_executed": _stock(5407, 3, "Successful sudo executed.", ("syslog", "sudo"), ("T1548.003",), file="0020-syslog_rules.xml"),
    # Web access log (0245-web_rules.xml)
    "web_400": _stock(31101, 5, "Web server 400 error code.", ("web", "accesslog", "attack"), file="0245-web_rules.xml"),
    "web_500": _stock(31122, 5, "Web server 500 error code (Internal Error).", ("web", "accesslog", "system_error"), file="0245-web_rules.xml"),
    "web_5xx": _stock(31120, 5, "Web server 500 error code (server error).", ("web", "accesslog"), file="0245-web_rules.xml"),
    "web_sql_injection": _stock(31103, 7, "SQL injection attempt.", ("web", "accesslog", "attack", "sql_injection"), ("T1190",), file="0245-web_rules.xml"),
    "web_common_attack": _stock(31104, 6, "Common web attack.", ("web", "accesslog", "attack"), ("T1190",), file="0245-web_rules.xml"),
    "web_xss": _stock(31105, 6, "XSS (Cross Site Scripting) attempt.", ("web", "accesslog", "attack"), ("T1190",), file="0245-web_rules.xml"),
    "web_attack_success": _stock(31106, 6, "A web attack returned code 200 (success).", ("web", "accesslog", "attack"), ("T1190",), file="0245-web_rules.xml"),
    "web_request": _custom(100300, 3, "nginx: web request", ("web", "accesslog")),
    # OpenVPN (0400-openvpn_rules.xml + custom)
    "openvpn_login": _stock(81801, 3, "OpenVPN: User logged in", ("openvpn", "authentication_success"), ("T1078",), file="0400-openvpn_rules.xml"),
    "openvpn_auth_failed": _custom(100400, 5, "OpenVPN: Username/password authentication failed", ("openvpn", "authentication_failed"), ("T1110",)),
    "openvpn_address_assigned": _custom(100401, 3, "OpenVPN: Client assigned a virtual address", ("openvpn",)),
    "openvpn_disconnected": _custom(100402, 3, "OpenVPN: Client disconnected", ("openvpn",)),
    # pfSense / Suricata (0540-pfsense_rules.xml, 0475-suricata_rules.xml)
    "pf_block": _stock(87701, 5, "pfSense firewall drop event.", ("pfsense", "firewall_block"), file="0540-pfsense_rules.xml"),
    "pf_pass": _custom(100700, 3, "pfSense firewall pass event.", ("pfsense", "firewall_pass")),
    "suricata_alert": _stock(86601, 3, "Suricata: Alert - $(alert.signature)", ("ids", "suricata"), file="0475-suricata_rules.xml"),
    # Mail, custom
    "mail_attachment": _custom(100500, 4, "Postfix: inbound message with attachment", ("postfix", "mail")),
    "mail_filter_passed": _custom(100501, 3, "Mail content filter: message passed", ("mail", "content_filter")),
    "mail_filter_blocked": _custom(100502, 8, "Mail content filter: message blocked", ("mail", "content_filter")),
    # PostgreSQL (0300-postgresql_rules.xml + custom)
    "pg_auth_success": _stock(50511, 3, "PostgreSQL: Database authentication success.", ("postgresql_log", "authentication_success"), ("T1078",), file="0300-postgresql_rules.xml"),
    "pg_auth_failed": _stock(50512, 9, "PostgreSQL: Database authentication failure.", ("postgresql_log", "authentication_failed"), file="0300-postgresql_rules.xml"),
    "pg_copy_to_stdout": _custom(100600, 7, "PostgreSQL: bulk export (COPY ... TO STDOUT)", ("postgresql_log", "data_export"), ("T1005",)),
}


# ── Small deterministic helpers ──────────────────

def stable_int(*parts: Any, modulo: int) -> int:
    """A deterministic integer in [0, modulo) from the inputs, so builders need no randomness."""
    digest = hashlib.sha256("|".join(str(p) for p in parts).encode()).digest()
    return int.from_bytes(digest[:8], "big") % modulo


def pick_int(rng: Optional[random.Random], low: int, high: int, *seed: Any) -> int:
    """rng.randint(low, high) when the caller passes an rng; otherwise a stable value derived from `seed`."""
    if rng is not None:
        return rng.randint(low, high)
    return low + stable_int(*seed, modulo=high - low + 1)


def stable_hex(*parts: Any, length: int = 32) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:length]


def iso_z(ts: datetime, *, digits: int = 3) -> str:
    """ISO-8601 UTC with a trailing Z, e.g. 2026-10-27T10:00:01.123Z (digits = fractional-second places)."""
    ts = ts.astimezone(timezone.utc)
    base = ts.strftime("%Y-%m-%dT%H:%M:%S")
    if digits:
        base += "." + f"{ts.microsecond:06d}{'0' * max(0, digits - 6)}"[:digits]
    return base + "Z"


def local_time(org: Org, ts: datetime) -> datetime:
    return ts.astimezone(ZoneInfo(org.timezone))


def syslog_stamp(org: Org, ts: datetime) -> str:
    """'Oct 27 15:30:01': the BSD syslog header time, in the company's local timezone."""
    local = local_time(org, ts)
    return f"{local:%b} {local.day:>2} {local:%H:%M:%S}"


def syslog_line(org: Org, asset: Asset, ts: datetime, program: str, message: str, pid: Optional[int] = None) -> str:
    tag = f"{program}[{pid}]" if pid is not None else program
    return f"{syslog_stamp(org, ts)} {asset.hostname} {tag}: {message}"


def predecoder(org: Org, asset: Asset, ts: datetime, program: str) -> dict:
    return {"program_name": program, "timestamp": syslog_stamp(org, ts), "hostname": asset.hostname}


# ── The envelope ─────────────────────────────────

def alert(
    org: Org,
    asset: Asset,
    timestamp: datetime,
    *,
    rule: Rule,
    decoder: dict,
    location: str,
    data: Optional[dict] = None,
    full_log: Optional[str] = None,
    predecoder: Optional[dict] = None,
    description: Optional[str] = None,
    firedtimes: int = 1,
    simulation: Optional[dict] = None,
    rng: Optional[random.Random] = None,
) -> dict:
    """
    One Wazuh 4.x alert as alerts.json holds it. `description` overrides
    the rule's when Wazuh expands a $(field) placeholder in it.
    """
    techniques = [MITRE[t][0] for t in rule.mitre if t in MITRE]
    tactics: list[str] = []
    for t in rule.mitre:
        for tactic in MITRE.get(t, ("", ()))[1]:
            if tactic not in tactics:
                tactics.append(tactic)

    rule_block: dict[str, Any] = {
        "level": rule.level,
        "description": description or rule.description,
        "id": str(rule.id),
        "firedtimes": firedtimes,
        "mail": rule.level >= 12,
        "groups": list(rule.groups),
    }
    if rule.mitre:
        rule_block["mitre"] = {"id": list(rule.mitre), "tactic": tactics, "technique": techniques}

    epoch = int(timestamp.timestamp())
    offset = pick_int(rng, 1000, 99_999_999, "alert", asset.hostname, iso_z(timestamp, digits=6), rule.id, full_log, data)
    manager = org.manager

    payload: dict[str, Any] = {
        "timestamp": iso_z(timestamp),
        "rule": rule_block,
        "agent": {"id": asset.wazuh_agent_id or "000", "name": asset.hostname, "ip": asset.ip},
        "manager": {"name": manager.hostname},
        "id": f"{epoch}.{offset}",
    }
    if full_log is not None:
        payload["full_log"] = full_log
    if predecoder is not None:
        payload["predecoder"] = predecoder
    payload["decoder"] = decoder
    if data:
        payload["data"] = data
    payload["location"] = location
    if simulation is not None:
        payload["simulation"] = simulation
    return payload
