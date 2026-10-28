"""
SafeSOC — Adapter Semantic Mapping
Pure functions (no I/O) that read a raw Wazuh alert and resolve what
the event *means* — a canonical (LogType, EventAction) pair from
core/enums.py — plus the user, network, process and file fields a
source-native payload carries in source-specific places. The
correlation detectors key on these canonical actions, so this lives in
the backend: a real Wazuh deployment benefits, not just the simulator
(docs/decisions.md ADR-012).

Resolution order, first match wins:

a) Windows eventchannel (decoder windows_eventchannel; data.win.system
   eventID + channel)
     Security  4625            -> authentication / failed_login
               4624            -> authentication / login_success
               4634, 4647      -> authentication / logout
               4672            -> privilege      / privilege_assigned
               4688            -> process        / process_start
               4720            -> privilege      / account_created
               4728,4732,4756  -> privilege      / group_member_added
               1102            -> system         / audit_log_cleared
               6416            -> system         / usb_device_connected
     Sysmon    1               -> process        / process_start
               3               -> network        / outbound_connection
                                  (initiated true) or inbound_connection
               11              -> file           / file_create
               23              -> file           / file_delete
   user: targetUserName for 4624/4625/4634/4647/4720; subjectUserName
   (the actor) for 4672/4688/4728/4732/4756/1102/6416; Sysmon `user`
   without its DOMAIN\\ prefix. Group changes append "member: <memberName>,
   group: <targetUserName>" to the description.

b) auditd command execution (decoder auditd, rule group audit_command,
   e.g. stock rule 80792 "Audit: Command")  -> process / process_start
   process_name: basename of data.audit.exe; command_line: data.audit.execve
   a0..aN joined with spaces (fallback data.audit.command, the comm name);
   process_id: data.audit.pid; user: data.audit.acct, else the AUID="name"
   auditd's ENRICHED log format appends to the record in full_log, else
   "unknown" (Wazuh's decoder only extracts the numeric auid).

c) Wazuh rule.groups
     authentication_failed | invalid_login      -> authentication / failed_login
     authentication_success                     -> authentication / login_success
     suricata | ids                             -> network / ids_alert
     web | accesslog, with attack | sql_injection | web_scan | xss
                                                -> network / web_attack
     web | accesslog, otherwise                 -> network / web_request
     firewall_block | firewall_drop             -> network / connection_blocked
     firewall_pass                              -> network / outbound_connection or
                                                   inbound_connection (data.direction
                                                   if present, else internal source ->
                                                   public destination = outbound)
     sudo, dstuser root                         -> privilege / privilege_assigned
     sudo, any other dstuser                    -> process / process_start
     data_export                                -> network / db_export
     mail | postfix | content_filter            -> system / email_received
                                                   (user: local part of data.to)
     syscheck added / modified / deleted        -> file / file_create, file_modify,
                                                   file_delete (syscheck.event, or the
                                                   syscheck_entry_* group)

d) Decoder-specific: openvpn "client disconnected" (rule 100402) ->
   authentication / logout.

e) No match: no log_type/action is returned and the Wazuh adapter keeps
   its fallback (action = decoder name, log_type from its keyword
   table), so unknown events still ingest.

Network fields come from data.srcip|src_ip, srcport|src_port,
dstip|dest_ip, dstport|dest_port, protocol|proto (Suricata EVE uses the
underscored names). user falls back to data.dstuser|srcuser (sudo:
srcuser, the invoking user). Severity is never decided here — it stays
with the adapter's rule.level mapping.
"""

import ipaddress
import ntpath
import re
from typing import Any, Optional

from app.core.enums import EventAction, LogType

Classification = tuple[LogType, EventAction]

# ── a) Windows eventchannel ────────────────────────────────────

SYSMON_CHANNEL = "microsoft-windows-sysmon/operational"

_SECURITY_EVENTS: dict[str, Classification] = {
    "4625": (LogType.AUTHENTICATION, EventAction.FAILED_LOGIN),
    "4624": (LogType.AUTHENTICATION, EventAction.LOGIN_SUCCESS),
    "4634": (LogType.AUTHENTICATION, EventAction.LOGOUT),
    "4647": (LogType.AUTHENTICATION, EventAction.LOGOUT),
    "4672": (LogType.PRIVILEGE, EventAction.PRIVILEGE_ASSIGNED),
    "4688": (LogType.PROCESS, EventAction.PROCESS_START),
    "4720": (LogType.PRIVILEGE, EventAction.ACCOUNT_CREATED),
    "4728": (LogType.PRIVILEGE, EventAction.GROUP_MEMBER_ADDED),
    "4732": (LogType.PRIVILEGE, EventAction.GROUP_MEMBER_ADDED),
    "4756": (LogType.PRIVILEGE, EventAction.GROUP_MEMBER_ADDED),
    "1102": (LogType.SYSTEM, EventAction.AUDIT_LOG_CLEARED),
    "6416": (LogType.SYSTEM, EventAction.USB_DEVICE_CONNECTED),
}

_SYSMON_EVENTS: dict[str, Classification] = {
    "1": (LogType.PROCESS, EventAction.PROCESS_START),
    "11": (LogType.FILE, EventAction.FILE_CREATE),
    "23": (LogType.FILE, EventAction.FILE_DELETE),
}

_TARGET_USER_EVENTS = {"4624", "4625", "4634", "4647", "4720"}
_GROUP_MEMBER_EVENTS = {"4728", "4732", "4756"}
_LOGON_IP_EVENTS = {"4624", "4625"}
_IGNORED_LOGON_IPS = {"-", "::1", "127.0.0.1"}


def _clean(value: Any) -> Optional[str]:
    """A Windows eventdata value, or None for the "-"/empty placeholders Windows uses for 'not applicable'."""
    if value is None:
        return None
    text = str(value).strip()
    return None if text in ("", "-") else text


def _lower_keys(values: Any) -> dict[str, Any]:
    return {str(k).lower(): v for k, v in values.items()} if isinstance(values, dict) else {}


def _to_int(value: Any) -> Optional[int]:
    """int from a decimal or "0x"-prefixed hex string (Windows process IDs); None if neither."""
    if value is None or isinstance(value, bool):
        return None
    try:
        text = str(value).strip()
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def _basename(path: Optional[str]) -> Optional[str]:
    return ntpath.basename(path) or None if path else None


def _strip_domain(user: Optional[str]) -> Optional[str]:
    return user.rsplit("\\", 1)[-1] or None if user else None


def parse_sha256(hashes: Optional[str]) -> Optional[str]:
    """The SHA256 value from a Sysmon hashes string ("SHA1=..,MD5=..,SHA256=<hex>,IMPHASH=.."), lower-cased."""
    if not hashes:
        return None
    for part in str(hashes).split(","):
        name, _, value = part.partition("=")
        if name.strip().upper() == "SHA256" and value.strip():
            return value.strip().lower()
    return None


def _is_true(value: Any) -> bool:
    return value is True or str(value).strip().lower() == "true"


def _windows(data: dict[str, Any], description: str) -> Optional[dict[str, Any]]:
    win = _lower_keys(data.get("win"))
    system = _lower_keys(win.get("system"))
    event_id = str(system.get("eventid") or "").strip()
    channel = str(system.get("channel") or "").strip().lower()
    eventdata = _lower_keys(win.get("eventdata"))

    if channel == "security":
        classification = _SECURITY_EVENTS.get(event_id)
    elif channel == SYSMON_CHANNEL:
        if event_id == "3":
            action = EventAction.OUTBOUND_CONNECTION if _is_true(eventdata.get("initiated")) else EventAction.INBOUND_CONNECTION
            classification = (LogType.NETWORK, action)
        else:
            classification = _SYSMON_EVENTS.get(event_id)
    else:
        classification = None
    if classification is None:
        return None

    fields: dict[str, Any] = {"log_type": classification[0], "action": classification[1]}
    is_sysmon = channel == SYSMON_CHANNEL

    if is_sysmon:
        fields["user"] = _strip_domain(_clean(eventdata.get("user")))
    elif event_id in _TARGET_USER_EVENTS:
        fields["user"] = _clean(eventdata.get("targetusername"))
    else:
        # 1102 carries its actor under UserData/LogFileCleared, not EventData.
        cleared = _lower_keys(win.get("logfilecleared"))
        fields["user"] = _clean(eventdata.get("subjectusername")) or _clean(cleared.get("subjectusername"))

    if event_id in _GROUP_MEMBER_EVENTS and not is_sysmon:
        member = _clean(eventdata.get("membername")) or "unknown"
        group = _clean(eventdata.get("targetusername")) or "unknown"
        fields["description"] = f"{description} (member: {member}, group: {group})"

    if event_id in _LOGON_IP_EVENTS and not is_sysmon:
        ip = _clean(eventdata.get("ipaddress"))
        if ip and ip not in _IGNORED_LOGON_IPS:
            fields["source_ip"] = ip
            fields["source_port"] = _to_int(_clean(eventdata.get("ipport"))) or None

    if is_sysmon and event_id == "3":
        fields["source_ip"] = _clean(eventdata.get("sourceip"))
        fields["source_port"] = _to_int(eventdata.get("sourceport"))
        fields["destination_ip"] = _clean(eventdata.get("destinationip"))
        fields["destination_port"] = _to_int(eventdata.get("destinationport"))
        fields["protocol"] = _normalize_protocol(eventdata.get("protocol"))

    if is_sysmon or event_id == "4688":
        fields["process_name"] = _basename(_clean(eventdata.get("image")) or _clean(eventdata.get("newprocessname")))
        fields["command_line"] = _clean(eventdata.get("commandline"))
        fields["parent_process"] = _basename(
            _clean(eventdata.get("parentimage")) or _clean(eventdata.get("parentprocessname"))
        )
        # 4688's processId is the PARENT's; newProcessId is the process created.
        fields["process_id"] = _to_int(eventdata.get("newprocessid") or eventdata.get("processid"))
        fields["file_path"] = _clean(eventdata.get("targetfilename"))
        fields["file_hash"] = parse_sha256(eventdata.get("hashes"))

    return fields


# ── b) auditd command execution ────────────────────────────────

_AUDIT_COMMAND_GROUP = "audit_command"
# auditd's ENRICHED log format (the default since audit 2.6) appends the
# resolved names to each record, e.g. AUID="karthik.reddy" UID="root".
_ENRICHED_AUID = re.compile(r'\bAUID="([^"]+)"')
_UNSET_AUID_NAMES = {"unset", "4294967295", "-1"}


def _execve_command_line(audit: dict[str, Any]) -> Optional[str]:
    """a0..aN in numeric order. Gaps are normal: auditd hex-encodes an argument holding a space, which Wazuh doesn't decode."""
    execve = audit.get("execve") if isinstance(audit.get("execve"), dict) else {}
    indexed = sorted(
        (int(key[1:]), str(value)) for key, value in execve.items()
        if str(key).startswith("a") and str(key)[1:].isdigit() and value not in (None, "")
    )
    return " ".join(value for _, value in indexed) or None


def _auditd(raw: dict[str, Any], data: dict[str, Any], groups: set[str]) -> Optional[dict[str, Any]]:
    if _AUDIT_COMMAND_GROUP not in groups:
        return None
    audit = data.get("audit") if isinstance(data.get("audit"), dict) else {}
    exe = audit.get("exe")
    if not exe and not audit.get("execve"):
        return None  # e.g. 80793 (passwd account lock) shares the group but runs no command

    enriched = _ENRICHED_AUID.search(str(raw.get("full_log") or ""))
    auid_name = enriched.group(1) if enriched and enriched.group(1) not in _UNSET_AUID_NAMES else None
    return {
        "log_type": LogType.PROCESS, "action": EventAction.PROCESS_START,
        "process_name": ntpath.basename(str(exe)) or None if exe else None,
        "command_line": _execve_command_line(audit) or audit.get("command"),
        "process_id": _to_int(audit.get("pid")),
        "user": audit.get("acct") or auid_name or "unknown",
    }


# ── c) Wazuh rule groups ───────────────────────────────────────

_WEB_GROUPS = {"web", "accesslog"}
_WEB_ATTACK_GROUPS = {"attack", "sql_injection", "web_scan", "xss"}
_MAIL_GROUPS = {"mail", "postfix", "content_filter"}
_SYSCHECK_EVENTS: dict[str, EventAction] = {
    "added": EventAction.FILE_CREATE,
    "modified": EventAction.FILE_MODIFY,
    "deleted": EventAction.FILE_DELETE,
}


def _is_internal(ip: Optional[str]) -> bool:
    try:
        return ip is not None and not ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _firewall_pass_direction(data: dict[str, Any], src_ip: Optional[str], dst_ip: Optional[str]) -> EventAction:
    direction = str(data.get("direction") or "").strip().lower()
    if direction in ("out", "outbound"):
        return EventAction.OUTBOUND_CONNECTION
    if direction in ("in", "inbound"):
        return EventAction.INBOUND_CONNECTION
    # Wazuh's pf decoder doesn't extract the filterlog direction: infer it.
    if _is_internal(src_ip) and dst_ip and not _is_internal(dst_ip):
        return EventAction.OUTBOUND_CONNECTION
    return EventAction.INBOUND_CONNECTION


def _by_groups(raw: dict[str, Any], groups: set[str], data: dict[str, Any], network: dict[str, Any]) -> Optional[dict[str, Any]]:
    if groups & {"authentication_failed", "invalid_login"}:
        return {"log_type": LogType.AUTHENTICATION, "action": EventAction.FAILED_LOGIN}
    if "authentication_success" in groups:
        return {"log_type": LogType.AUTHENTICATION, "action": EventAction.LOGIN_SUCCESS}
    if groups & {"suricata", "ids"}:
        return {"log_type": LogType.NETWORK, "action": EventAction.IDS_ALERT}
    if groups & _WEB_GROUPS:
        action = EventAction.WEB_ATTACK if groups & _WEB_ATTACK_GROUPS else EventAction.WEB_REQUEST
        return {"log_type": LogType.NETWORK, "action": action}
    if groups & {"firewall_block", "firewall_drop"}:
        return {"log_type": LogType.NETWORK, "action": EventAction.CONNECTION_BLOCKED}
    if "firewall_pass" in groups:
        action = _firewall_pass_direction(data, network.get("source_ip"), network.get("destination_ip"))
        return {"log_type": LogType.NETWORK, "action": action}
    if "sudo" in groups:
        to_root = str(data.get("dstuser") or "").strip().lower() == "root"
        classification = (
            (LogType.PRIVILEGE, EventAction.PRIVILEGE_ASSIGNED) if to_root
            else (LogType.PROCESS, EventAction.PROCESS_START)
        )
        # The invoking user (srcuser) is who acted; dstuser is just who they ran as.
        return {
            "log_type": classification[0], "action": classification[1],
            "user": data.get("srcuser") or data.get("dstuser"),
            "command_line": data.get("command"),
        }
    if "data_export" in groups:
        return {"log_type": LogType.NETWORK, "action": EventAction.DB_EXPORT}
    if groups & _MAIL_GROUPS:
        return {"log_type": LogType.SYSTEM, "action": EventAction.EMAIL_RECEIVED, "user": _mailbox_user(data.get("to"))}

    syscheck = raw.get("syscheck") if isinstance(raw.get("syscheck"), dict) else {}
    syscheck_event = str(syscheck.get("event") or "").strip().lower()
    if syscheck_event not in _SYSCHECK_EVENTS:
        syscheck_event = next((e for e in _SYSCHECK_EVENTS if f"syscheck_entry_{e}" in groups), "")
    if syscheck_event:
        return {
            "log_type": LogType.FILE, "action": _SYSCHECK_EVENTS[syscheck_event],
            "file_path": syscheck.get("path"), "file_hash": syscheck.get("sha256_after"),
        }
    return None


def _mailbox_user(recipient: Any) -> Optional[str]:
    """The local part of the (first) recipient: "<Neha.Sharma@emberbay.example>" -> "neha.sharma"."""
    if not recipient:
        return None
    first = str(recipient).split(",")[0].strip().strip("<>").strip()
    local = first.split("@", 1)[0].strip()
    return local.lower() or None


# ── d) Decoder-specific leftovers ──────────────────────────────

_OPENVPN_DISCONNECTED_RULE = "100402"


def _decoder_specific(decoder_name: str, rule: dict[str, Any]) -> Optional[dict[str, Any]]:
    if decoder_name == "openvpn" and (
        str(rule.get("id")) == _OPENVPN_DISCONNECTED_RULE
        or "client disconnected" in str(rule.get("description") or "").lower()
    ):
        return {"log_type": LogType.AUTHENTICATION, "action": EventAction.LOGOUT}
    return None


# ── Entry point ────────────────────────────────────────────────

_HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"}


def _first(data: dict[str, Any], *keys: str) -> Any:
    return next((data[k] for k in keys if data.get(k) not in (None, "")), None)


def _normalize_protocol(value: Any) -> Optional[str]:
    """Transport protocol, lower-cased. Wazuh's web-accesslog decoder stores the HTTP method as "protocol" — dropped."""
    if value in (None, ""):
        return None
    text = str(value).strip()
    return None if text.upper() in _HTTP_METHODS else text.lower()


def _network_fields(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "source_ip": _first(data, "srcip", "src_ip"),
        "source_port": _to_int(_first(data, "srcport", "src_port")),
        "destination_ip": _first(data, "dstip", "dest_ip"),
        "destination_port": _to_int(_first(data, "dstport", "dest_port")),
        "protocol": _normalize_protocol(_first(data, "protocol", "proto")),
    }


def map_wazuh_event(raw: dict[str, Any]) -> dict[str, Any]:
    """
    NormalizedLog fields resolved from a raw Wazuh alert. Only fields
    that could be resolved are returned (never a None value), so the
    caller merges this over its own defaults. "log_type"/"action" are
    present only when one of rules a)-d) matched; the caller keeps its
    fallback otherwise. Never raises for a sparse/malformed payload.
    """
    rule = raw.get("rule") if isinstance(raw.get("rule"), dict) else {}
    data = raw.get("data") if isinstance(raw.get("data"), dict) else {}
    decoder = raw.get("decoder") if isinstance(raw.get("decoder"), dict) else {}
    decoder_name = str(decoder.get("name") or "")
    groups = {str(g).lower() for g in (rule.get("groups") or [])}
    description = rule.get("description") or "Wazuh alert"

    fields = _network_fields(data)
    fields["user"] = data.get("dstuser") or data.get("srcuser")

    semantic = None
    if decoder_name == "windows_eventchannel":
        semantic = _windows(data, description)
    if semantic is None and decoder_name == "auditd":
        semantic = _auditd(raw, data, groups)
    if semantic is None:
        semantic = _by_groups(raw, groups, data, fields)
    if semantic is None:
        semantic = _decoder_specific(decoder_name, rule)

    for key, value in (semantic or {}).items():
        if value is not None:
            fields[key] = value

    resolved = {k: v for k, v in fields.items() if v is not None}
    for key in ("log_type", "action"):
        if key in resolved:
            resolved[key] = resolved[key].value
    return resolved
