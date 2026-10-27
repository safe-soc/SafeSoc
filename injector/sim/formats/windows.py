"""
SafeSOC — Simulator Windows Event Builders
Windows Security and Sysmon events as the Wazuh agent ships them
(decoder windows_eventchannel): data.win.system + data.win.eventdata
with the event's real field names, camelCased the way Wazuh does it.
All values are strings, as in a real Wazuh alert.
"""

from __future__ import annotations

import random
from datetime import datetime
from typing import Optional

from injector.sim.formats.wazuh_common import RULES, Rule, alert, iso_z, pick_int, stable_hex
from injector.sim.org import Asset, Org, User

__all__ = [
    "logon_success", "logon_failure", "special_privileges", "process_created", "user_created",
    "member_added_global_group", "member_added_local_group", "audit_log_cleared", "usb_device_recognized",
    "sysmon_process_create", "sysmon_network_connect", "sysmon_file_create", "sysmon_file_delete",
]

DECODER = {"name": "windows_eventchannel"}
SECURITY_CHANNEL = "Security"
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SECURITY_PROVIDER = ("Microsoft-Windows-Security-Auditing", "{54849625-5478-4994-a5ba-3e3b0328c30d}")
SYSMON_PROVIDER = ("Microsoft-Windows-Sysmon", "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}")

# Event Log keywords: audit success / audit failure.
AUDIT_SUCCESS = ("0x8020000000000000", "AUDIT_SUCCESS")
AUDIT_FAILURE = ("0x8010000000000000", "AUDIT_FAILURE")

# Built-in local groups: well-known SID and the stock rule Wazuh fires when one changes.
BUILTIN_GROUPS = {
    "Administrators": ("S-1-5-32-544", "win_administrators_changed"),
    "Users": ("S-1-5-32-545", "win_users_group_changed"),
    "Remote Desktop Users": ("S-1-5-32-555", "win_rdp_users_changed"),
}
# Well-known domain group RIDs and the stock rule for each.
DOMAIN_GROUPS = {
    "Domain Admins": (512, "win_domain_admins_changed"),
    "Domain Users": (513, "win_domain_users_changed"),
}

LOGON_FAILURE_STATUS = {
    # subStatus: (status, failureReason message ID)
    "0xc000006a": ("0xc000006d", "%%2313"),  # bad password
    "0xc0000064": ("0xc000006d", "%%2313"),  # no such user
    "0xc0000234": ("0xc0000234", "%%2307"),  # account locked out
}


def _logon_id(asset: Asset, ts: datetime, *seed, rng: Optional[random.Random] = None) -> str:
    return hex(pick_int(rng, 0x100000, 0xFFFFFF, "logon", asset.hostname, iso_z(ts, digits=6), *seed))


def _guid(*parts) -> str:
    h = stable_hex(*parts)
    return "{" + f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}".upper() + "}"


def _system(
    org: Org, asset: Asset, ts: datetime, *, event_id: int, channel: str, provider: tuple[str, str], task: str,
    keywords: tuple[str, str], message: str, rng: Optional[random.Random], level: str = "0", opcode: str = "0",
    version: str = "0",
) -> dict:
    return {
        "providerName": provider[0],
        "providerGuid": provider[1],
        "eventID": str(event_id),
        "version": version,
        "level": level,
        "task": task,
        "opcode": opcode,
        "keywords": keywords[0],
        "systemTime": iso_z(ts, digits=7),
        "eventRecordID": str(pick_int(rng, 100_000, 9_999_999, "record", asset.hostname, channel, iso_z(ts, digits=6), event_id)),
        "processID": "4" if channel == SYSMON_CHANNEL else "740",
        "threadID": str(pick_int(rng, 100, 9999, "thread", asset.hostname, iso_z(ts, digits=6), event_id)),
        "channel": channel,
        "computer": org.fqdn(asset),
        "severityValue": keywords[1] if channel == SECURITY_CHANNEL else "INFORMATION",
        "message": message,
    }


def _event(org, asset, ts, rule: Rule, system: dict, eventdata: dict, simulation, rng, *, extra: Optional[dict] = None,
           description: Optional[str] = None) -> dict:
    win = {"system": system, "eventdata": {k: v for k, v in eventdata.items() if v is not None}}
    if extra:
        win.update(extra)
    return alert(
        org, asset, ts, rule=rule, decoder=DECODER, location="EventChannel", data={"win": win},
        description=description, simulation=simulation, rng=rng,
    )


def _subject(org: Org, actor: Optional[User], asset: Asset, logon_id: str) -> dict:
    """The Subject* block; SYSTEM (the machine account) when no user acted."""
    if actor is None:
        return {
            "subjectUserSid": "S-1-5-18",
            "subjectUserName": f"{asset.hostname}$",
            "subjectDomainName": org.netbios_domain,
            "subjectLogonId": "0x3e7",
        }
    return {
        "subjectUserSid": org.user_sid(actor),
        "subjectUserName": actor.username,
        "subjectDomainName": org.netbios_domain,
        "subjectLogonId": logon_id,
    }


# ── Security log ─────────────────────────────────

def logon_success(
    org: Org, asset: Asset, user: User, timestamp: datetime, *, logon_type: int = 2, ip_address: str = "127.0.0.1",
    ip_port: str = "0", workstation_name: Optional[str] = None, authentication_package: str = "Negotiate",
    simulation: Optional[dict] = None, rng: Optional[random.Random] = None,
) -> dict:
    """4624 An account was successfully logged on (2 interactive, 3 network, 10 RemoteInteractive/RDP)."""
    logon_id = _logon_id(asset, timestamp, user.username, rng=rng)
    workstation = workstation_name if workstation_name is not None else asset.hostname
    rule = RULES["win_workstation_logon_success" if logon_type == 2 and workstation else "win_logon_success"]
    process = r"C:\Windows\System32\svchost.exe" if logon_type == 10 else (
        r"C:\Windows\System32\lsass.exe" if logon_type == 3 else r"C:\Windows\System32\winlogon.exe")
    eventdata = {
        "subjectUserSid": "S-1-5-18" if logon_type != 3 else "S-1-0-0",
        "subjectUserName": f"{asset.hostname}$" if logon_type != 3 else "-",
        "subjectDomainName": org.netbios_domain if logon_type != 3 else "-",
        "subjectLogonId": "0x3e7" if logon_type != 3 else "0x0",
        "targetUserSid": org.user_sid(user),
        "targetUserName": user.username,
        "targetDomainName": org.netbios_domain,
        "targetLogonId": logon_id,
        "logonType": str(logon_type),
        "logonProcessName": "User32" if logon_type in (2, 10) else "NtLmSsp",
        "authenticationPackageName": authentication_package,
        "workstationName": workstation,
        "logonGuid": _guid("logonguid", asset.hostname, user.username, iso_z(timestamp, digits=6)),
        "transmittedServices": "-",
        "lmPackageName": "NTLM V2" if authentication_package == "NTLM" else "-",
        "keyLength": "128" if authentication_package == "NTLM" else "0",
        "processId": "0x0" if logon_type == 3 else "0x2f4",
        "processName": "-" if logon_type == 3 else process,
        "ipAddress": ip_address,
        "ipPort": ip_port,
        "impersonationLevel": "%%1833",
        "virtualAccount": "%%1843",
        "elevatedToken": "%%1842" if "Domain Admins" in user.groups else "%%1843",
    }
    system = _system(org, asset, timestamp, event_id=4624, channel=SECURITY_CHANNEL, provider=SECURITY_PROVIDER,
                     task="12544", keywords=AUDIT_SUCCESS, version="2", rng=rng,
                     message="An account was successfully logged on.")
    return _event(org, asset, timestamp, rule, system, eventdata, simulation, rng)


def logon_failure(
    org: Org, asset: Asset, timestamp: datetime, *, target_user_name: str, logon_type: int = 3,
    sub_status: str = "0xc000006a", ip_address: str = "-", ip_port: str = "0", workstation_name: str = "-",
    authentication_package: str = "NTLM", simulation: Optional[dict] = None, rng: Optional[random.Random] = None,
) -> dict:
    """
    4625 An account failed to log on. sub_status: 0xc000006a bad password,
    0xc0000064 no such user, 0xc0000234 locked out. Takes a user NAME, not
    a User, because failed logons are often for accounts that don't exist.
    """
    status, failure_reason = LOGON_FAILURE_STATUS.get(sub_status.lower(), ("0xc000006d", "%%2313"))
    eventdata = {
        "subjectUserSid": "S-1-0-0",
        "subjectUserName": "-",
        "subjectDomainName": "-",
        "subjectLogonId": "0x0",
        "targetUserSid": "S-1-0-0",
        "targetUserName": target_user_name,
        "targetDomainName": org.netbios_domain,
        "status": status,
        "failureReason": failure_reason,
        "subStatus": sub_status.lower(),
        "logonType": str(logon_type),
        "logonProcessName": "NtLmSsp" if authentication_package == "NTLM" else "User32",
        "authenticationPackageName": authentication_package,
        "workstationName": workstation_name,
        "transmittedServices": "-",
        "lmPackageName": "-",
        "keyLength": "0",
        "processId": "0x0",
        "processName": "-",
        "ipAddress": ip_address,
        "ipPort": ip_port,
    }
    system = _system(org, asset, timestamp, event_id=4625, channel=SECURITY_CHANNEL, provider=SECURITY_PROVIDER,
                     task="12544", keywords=AUDIT_FAILURE, rng=rng, message="An account failed to log on.")
    return _event(org, asset, timestamp, RULES["win_logon_failure"], system, eventdata, simulation, rng)


def special_privileges(
    org: Org, asset: Asset, user: User, timestamp: datetime, *, logon_id: Optional[str] = None,
    privileges: str = "SeSecurityPrivilege\n\t\t\tSeBackupPrivilege\n\t\t\tSeRestorePrivilege\n\t\t\tSeTakeOwnershipPrivilege\n\t\t\tSeDebugPrivilege\n\t\t\tSeSystemEnvironmentPrivilege\n\t\t\tSeLoadDriverPrivilege\n\t\t\tSeImpersonatePrivilege\n\t\t\tSeDelegateSessionUserImpersonatePrivilege\n\t\t\tSeEnableDelegationPrivilege",
    simulation: Optional[dict] = None, rng: Optional[random.Random] = None,
) -> dict:
    """4672 Special privileges assigned to new logon (an administrative logon)."""
    eventdata = {
        "subjectUserSid": org.user_sid(user),
        "subjectUserName": user.username,
        "subjectDomainName": org.netbios_domain,
        "subjectLogonId": logon_id or _logon_id(asset, timestamp, user.username, rng=rng),
        "privilegeList": privileges,
    }
    system = _system(org, asset, timestamp, event_id=4672, channel=SECURITY_CHANNEL, provider=SECURITY_PROVIDER,
                     task="12548", keywords=AUDIT_SUCCESS, rng=rng, message="Special privileges assigned to new logon.")
    return _event(org, asset, timestamp, RULES["win_special_privileges"], system, eventdata, simulation, rng)


def process_created(
    org: Org, asset: Asset, user: User, timestamp: datetime, *, new_process_name: str, command_line: str,
    parent_process_name: str = r"C:\Windows\explorer.exe", new_process_id: Optional[int] = None,
    parent_process_id: Optional[int] = None, elevated: bool = False, logon_id: Optional[str] = None,
    simulation: Optional[dict] = None, rng: Optional[random.Random] = None,
) -> dict:
    """4688 A new process has been created (with command-line auditing enabled)."""
    seed = (asset.hostname, new_process_name, command_line, iso_z(timestamp, digits=6))
    pid = new_process_id if new_process_id is not None else pick_int(rng, 1000, 30000, "pid", *seed)
    ppid = parent_process_id if parent_process_id is not None else pick_int(rng, 1000, 30000, "ppid", *seed)
    eventdata = {
        **_subject(org, user, asset, logon_id or _logon_id(asset, timestamp, user.username, rng=rng)),
        "newProcessId": hex(pid),
        "newProcessName": new_process_name,
        "tokenElevationType": "%%1937" if elevated else "%%1938",
        "processId": hex(ppid),
        "commandLine": command_line,
        "targetUserSid": "S-1-0-0",
        "targetUserName": "-",
        "targetDomainName": "-",
        "targetLogonId": "0x0",
        "parentProcessName": parent_process_name,
        "mandatoryLabel": "S-1-16-12288" if elevated else "S-1-16-8192",
    }
    system = _system(org, asset, timestamp, event_id=4688, channel=SECURITY_CHANNEL, provider=SECURITY_PROVIDER,
                     task="13312", keywords=AUDIT_SUCCESS, version="2", rng=rng, message="A new process has been created.")
    return _event(org, asset, timestamp, RULES["win_process_created"], system, eventdata, simulation, rng)


def user_created(
    org: Org, dc: Asset, actor: User, timestamp: datetime, *, new_user_name: str, new_user_rid: int,
    display_name: str = "%%1793", simulation: Optional[dict] = None, rng: Optional[random.Random] = None,
) -> dict:
    """4720 A user account was created (logged on the domain controller)."""
    eventdata = {
        "targetUserName": new_user_name,
        "targetDomainName": org.netbios_domain,
        "targetSid": f"{org.domain_sid}-{new_user_rid}",
        **_subject(org, actor, dc, _logon_id(dc, timestamp, actor.username, rng=rng)),
        "privilegeList": "-",
        "samAccountName": new_user_name,
        "displayName": display_name,
        "userPrincipalName": f"{new_user_name}@{org.domain}",
        "homeDirectory": "%%1793",
        "homePath": "%%1793",
        "scriptPath": "%%1793",
        "profilePath": "%%1793",
        "userWorkstations": "%%1793",
        "passwordLastSet": "%%1794",
        "accountExpires": "%%1794",
        "primaryGroupId": "513",
        "allowedToDelegateTo": "-",
        "oldUacValue": "0x0",
        "newUacValue": "0x15",
        "userAccountControl": "\r\n\t\t%%2080\r\n\t\t%%2082\r\n\t\t%%2084",
        "userParameters": "%%1793",
        "sidHistory": "-",
        "logonHours": "%%1797",
    }
    system = _system(org, dc, timestamp, event_id=4720, channel=SECURITY_CHANNEL, provider=SECURITY_PROVIDER,
                     task="13824", keywords=AUDIT_SUCCESS, rng=rng, message="A user account was created.")
    return _event(org, dc, timestamp, RULES["win_user_created"], system, eventdata, simulation, rng)


def _member_dn(org: Org, member_name: str) -> str:
    dc = ",".join(f"DC={part}" for part in org.domain.split("."))
    return f"CN={member_name},CN=Users,{dc}"


def member_added_global_group(
    org: Org, dc: Asset, actor: User, timestamp: datetime, *, member_name: str, member_sid: str,
    group: str = "Domain Admins", group_rid: Optional[int] = None, simulation: Optional[dict] = None,
    rng: Optional[random.Random] = None,
) -> dict:
    """4728 A member was added to a security-enabled global group (e.g. Domain Admins -> stock rule 60159, level 12)."""
    known_rid, rule_name = DOMAIN_GROUPS.get(group, (group_rid, "win_global_group_member_added"))
    rid = group_rid if group_rid is not None else known_rid
    if rid is None:
        raise ValueError(f"group_rid is required for non-well-known group '{group}'")
    eventdata = {
        "memberName": _member_dn(org, member_name),
        "memberSid": member_sid,
        "targetUserName": group,
        "targetDomainName": org.netbios_domain,
        "targetSid": f"{org.domain_sid}-{rid}",
        **_subject(org, actor, dc, _logon_id(dc, timestamp, actor.username, rng=rng)),
        "privilegeList": "-",
    }
    system = _system(org, dc, timestamp, event_id=4728, channel=SECURITY_CHANNEL, provider=SECURITY_PROVIDER,
                     task="13826", keywords=AUDIT_SUCCESS, rng=rng,
                     message="A member was added to a security-enabled global group.")
    return _event(org, dc, timestamp, RULES[rule_name], system, eventdata, simulation, rng)


def member_added_local_group(
    org: Org, asset: Asset, actor: User, timestamp: datetime, *, member_name: str, member_sid: str,
    group: str = "Administrators", group_sid: Optional[str] = None, simulation: Optional[dict] = None,
    rng: Optional[random.Random] = None,
) -> dict:
    """4732 A member was added to a security-enabled local group (Administrators -> stock rule 60154, level 12)."""
    known_sid, rule_name = BUILTIN_GROUPS.get(group, (group_sid, "win_local_group_member_added"))
    sid = group_sid or known_sid
    if sid is None:
        raise ValueError(f"group_sid is required for non-built-in group '{group}'")
    eventdata = {
        "memberName": _member_dn(org, member_name),
        "memberSid": member_sid,
        "targetUserName": group,
        "targetDomainName": "Builtin" if sid.startswith("S-1-5-32-") else org.netbios_domain,
        "targetSid": sid,
        **_subject(org, actor, asset, _logon_id(asset, timestamp, actor.username, rng=rng)),
        "privilegeList": "-",
    }
    system = _system(org, asset, timestamp, event_id=4732, channel=SECURITY_CHANNEL, provider=SECURITY_PROVIDER,
                     task="13826", keywords=AUDIT_SUCCESS, rng=rng,
                     message="A member was added to a security-enabled local group.")
    return _event(org, asset, timestamp, RULES[rule_name], system, eventdata, simulation, rng)


def audit_log_cleared(
    org: Org, asset: Asset, actor: User, timestamp: datetime, *, simulation: Optional[dict] = None,
    rng: Optional[random.Random] = None,
) -> dict:
    """1102 The audit log was cleared. The subject is in UserData/LogFileCleared, not EventData."""
    system = _system(org, asset, timestamp, event_id=1102, channel=SECURITY_CHANNEL,
                     provider=("Microsoft-Windows-Eventlog", "{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}"),
                     task="104", keywords=("0x4020000000000000", "AUDIT_SUCCESS"), level="4", opcode="0", rng=rng,
                     message="The audit log was cleared.")
    cleared = _subject(org, actor, asset, _logon_id(asset, timestamp, actor.username, rng=rng))
    return _event(org, asset, timestamp, RULES["win_audit_log_cleared"], system, {}, simulation, rng,
                  extra={"logFileCleared": cleared})


def usb_device_recognized(
    org: Org, asset: Asset, timestamp: datetime, *, device_description: str = "USB Mass Storage Device",
    vendor_ids: str = r"USB\VID_0781&PID_5583&REV_0100", serial: str = "4C530001230512117354",
    simulation: Optional[dict] = None, rng: Optional[random.Random] = None,
) -> dict:
    """6416 A new external device was recognized by the system."""
    vid_pid = vendor_ids.split("&REV_")[0]
    eventdata = {
        **_subject(org, None, asset, "0x3e7"),
        "deviceId": rf"{vid_pid}\{serial}",
        "deviceDescription": device_description,
        "classId": "{36fc9e60-c465-11cf-8056-444553540000}",
        "className": "USB",
        "vendorIds": vendor_ids,
        "compatibleIds": r"USB\Class_08&SubClass_06&Prot_50",
        "locationInformation": "Port_#0002.Hub_#0001",
    }
    system = _system(org, asset, timestamp, event_id=6416, channel=SECURITY_CHANNEL, provider=SECURITY_PROVIDER,
                     task="13316", keywords=AUDIT_SUCCESS, rng=rng,
                     message="A new external device was recognized by the system.")
    return _event(org, asset, timestamp, RULES["win_usb_device"], system, eventdata, simulation, rng)


# ── Sysmon ───────────────────────────────────────

def _sysmon_utc(ts: datetime) -> str:
    return iso_z(ts, digits=3).replace("T", " ").rstrip("Z")


def _sysmon_user(org: Org, user: User) -> str:
    return f"{org.netbios_domain}\\{user.username}"


def _process_guid(asset: Asset, image: str, pid: int) -> str:
    return _guid("procguid", asset.hostname, image, pid)


def _pid(rng, asset, image, ts, process_id) -> int:
    return process_id if process_id is not None else pick_int(rng, 1000, 30000, "pid", asset.hostname, image, iso_z(ts, digits=6))


def _sysmon_system(org, asset, ts, event_id, task, message, rng) -> dict:
    return _system(org, asset, ts, event_id=event_id, channel=SYSMON_CHANNEL, provider=SYSMON_PROVIDER, task=task,
                   keywords=("0x8000000000000000", "INFORMATION"), level="4", version="5", rng=rng, message=message)


def sysmon_process_create(
    org: Org, asset: Asset, user: User, timestamp: datetime, *, image: str, command_line: str, parent_image: str,
    parent_command_line: str, hashes: str, current_directory: Optional[str] = None, process_id: Optional[int] = None,
    parent_process_id: Optional[int] = None, integrity_level: str = "Medium", original_file_name: Optional[str] = None,
    simulation: Optional[dict] = None, rng: Optional[random.Random] = None,
) -> dict:
    """Sysmon Event 1: Process creation. `hashes` is Sysmon's 'SHA1=..,MD5=..,SHA256=..,IMPHASH=..' string."""
    pid = _pid(rng, asset, image, timestamp, process_id)
    ppid = _pid(rng, asset, parent_image, timestamp, parent_process_id)
    file_name = image.rsplit("\\", 1)[-1]
    eventdata = {
        "ruleName": "-",
        "utcTime": _sysmon_utc(timestamp),
        "processGuid": _process_guid(asset, image, pid),
        "processId": str(pid),
        "image": image,
        "originalFileName": original_file_name or file_name,
        "commandLine": command_line,
        "currentDirectory": current_directory or f"C:\\Users\\{user.username}\\",
        "user": _sysmon_user(org, user),
        "logonGuid": _guid("logonguid", asset.hostname, user.username),
        "logonId": _logon_id(asset, timestamp, user.username, "sysmon", rng=rng),
        "terminalSessionId": "1",
        "integrityLevel": integrity_level,
        "hashes": hashes,
        "parentProcessGuid": _process_guid(asset, parent_image, ppid),
        "parentProcessId": str(ppid),
        "parentImage": parent_image,
        "parentCommandLine": parent_command_line,
        "parentUser": _sysmon_user(org, user),
    }
    system = _sysmon_system(org, asset, timestamp, 1, "1", "Process Create", rng)
    return _event(org, asset, timestamp, RULES["sysmon_process_create"], system, eventdata, simulation, rng,
                  description=f"Sysmon - Event 1: Process creation {file_name}")


def sysmon_network_connect(
    org: Org, asset: Asset, user: User, timestamp: datetime, *, image: str, destination_ip: str, destination_port: int,
    protocol: str = "tcp", source_port: Optional[int] = None, destination_hostname: str = "-",
    destination_port_name: str = "-", process_id: Optional[int] = None, simulation: Optional[dict] = None,
    rng: Optional[random.Random] = None,
) -> dict:
    """Sysmon Event 3: Network connection detected (outbound, initiated by `image`)."""
    pid = _pid(rng, asset, image, timestamp, process_id)
    sport = source_port if source_port is not None else pick_int(
        rng, 49152, 65535, "sport", asset.hostname, destination_ip, iso_z(timestamp, digits=6))
    eventdata = {
        "ruleName": "-",
        "utcTime": _sysmon_utc(timestamp),
        "processGuid": _process_guid(asset, image, pid),
        "processId": str(pid),
        "image": image,
        "user": _sysmon_user(org, user),
        "protocol": protocol,
        "initiated": "true",
        "sourceIsIpv6": "false",
        "sourceIp": asset.ip,
        "sourceHostname": org.fqdn(asset),
        "sourcePort": str(sport),
        "sourcePortName": "-",
        "destinationIsIpv6": "false",
        "destinationIp": destination_ip,
        "destinationHostname": destination_hostname,
        "destinationPort": str(destination_port),
        "destinationPortName": destination_port_name,
    }
    system = _sysmon_system(org, asset, timestamp, 3, "3", "Network connection detected", rng)
    return _event(org, asset, timestamp, RULES["sysmon_network_connect"], system, eventdata, simulation, rng,
                  description=f"Sysmon - Event 3: Network connection to {destination_ip}:{destination_port} by {image}")


def sysmon_file_create(
    org: Org, asset: Asset, user: User, timestamp: datetime, *, image: str, target_filename: str,
    process_id: Optional[int] = None, simulation: Optional[dict] = None, rng: Optional[random.Random] = None,
) -> dict:
    """Sysmon Event 11: File created."""
    pid = _pid(rng, asset, image, timestamp, process_id)
    eventdata = {
        "ruleName": "-",
        "utcTime": _sysmon_utc(timestamp),
        "processGuid": _process_guid(asset, image, pid),
        "processId": str(pid),
        "image": image,
        "targetFilename": target_filename,
        "creationUtcTime": _sysmon_utc(timestamp),
        "user": _sysmon_user(org, user),
    }
    system = _sysmon_system(org, asset, timestamp, 11, "11", "File created", rng)
    return _event(org, asset, timestamp, RULES["sysmon_file_create"], system, eventdata, simulation, rng,
                  description=f"Sysmon - Event 11: FileCreate by {image}")


def sysmon_file_delete(
    org: Org, asset: Asset, user: User, timestamp: datetime, *, image: str, target_filename: str, hashes: str,
    is_executable: bool = False, process_id: Optional[int] = None, simulation: Optional[dict] = None,
    rng: Optional[random.Random] = None,
) -> dict:
    """Sysmon Event 23: File Delete archived."""
    pid = _pid(rng, asset, image, timestamp, process_id)
    eventdata = {
        "ruleName": "-",
        "utcTime": _sysmon_utc(timestamp),
        "processGuid": _process_guid(asset, image, pid),
        "processId": str(pid),
        "user": _sysmon_user(org, user),
        "image": image,
        "targetFilename": target_filename,
        "hashes": hashes,
        "isExecutable": "true" if is_executable else "false",
        "archived": "true",
    }
    system = _sysmon_system(org, asset, timestamp, 23, "23", "File Delete archived", rng)
    return _event(org, asset, timestamp, RULES["sysmon_file_delete"], system, eventdata, simulation, rng)
