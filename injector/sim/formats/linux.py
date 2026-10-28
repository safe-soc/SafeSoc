"""
SafeSOC — Simulator Linux (sshd / sudo / auditd) Builders
Ubuntu auth.log lines and auditd records wrapped as Wazuh alerts, with
data.* fields as Wazuh's sshd, sudo and auditd decoders extract them.
"""

from __future__ import annotations

import random
from datetime import datetime
from typing import Optional

from injector.sim.formats.wazuh_common import RULES, alert, iso_z, pick_int, predecoder, syslog_line
from injector.sim.org import Asset, Org, User

__all__ = ["ssh_failed_password", "ssh_invalid_user", "ssh_accepted_password", "sudo_command", "auditd_execve"]

AUTH_LOG = "/var/log/auth.log"
AUDIT_LOG = "/var/log/audit/audit.log"
# The key Wazuh's documented execve audit rule uses
# (-a exit,always -F arch=b64 -S execve -k audit-wazuh-c); the stock
# etc/lists/audit-keys maps it to "command", which is what rule 80792 checks.
AUDIT_COMMAND_KEY = "audit-wazuh-c"
# auditd's ENRICHED log format separates the raw record from the resolved names with 0x1d.
_ENRICHED_SEPARATOR = "\x1d"
# Wazuh's auditd decoder extracts EXECVE arguments a0..a7 only.
_DECODED_EXECVE_ARGS = 8


def _sshd_pid(rng, asset: Asset, ts: datetime, *seed) -> int:
    return pick_int(rng, 1000, 65000, "sshd", asset.hostname, iso_z(ts, digits=6), *seed)


def _sshd(org, asset, ts, *, rule_name, message, data, pid, simulation, rng) -> dict:
    return alert(
        org, asset, ts, rule=RULES[rule_name], decoder={"parent": "sshd", "name": "sshd"}, location=AUTH_LOG,
        full_log=syslog_line(org, asset, ts, "sshd", message, pid), predecoder=predecoder(org, asset, ts, "sshd"),
        data=data, simulation=simulation, rng=rng,
    )


def ssh_failed_password(
    org: Org, asset: Asset, timestamp: datetime, *, username: str, src_ip: str, src_port: Optional[int] = None,
    simulation: Optional[dict] = None, rng: Optional[random.Random] = None,
) -> dict:
    """'Failed password for <user> from <ip> port <n> ssh2' (rule 5716) for an account that exists."""
    port = src_port if src_port is not None else pick_int(rng, 32768, 60999, "sport", asset.hostname, src_ip, iso_z(timestamp, digits=6))
    pid = _sshd_pid(rng, asset, timestamp, src_ip, port)
    return _sshd(
        org, asset, timestamp, rule_name="sshd_auth_failed",
        message=f"Failed password for {username} from {src_ip} port {port} ssh2",
        data={"srcip": src_ip, "srcport": str(port), "dstuser": username},
        pid=pid, simulation=simulation, rng=rng,
    )


def ssh_invalid_user(
    org: Org, asset: Asset, timestamp: datetime, *, username: str, src_ip: str, src_port: Optional[int] = None,
    simulation: Optional[dict] = None, rng: Optional[random.Random] = None,
) -> dict:
    """'Invalid user <name> from <ip> port <n>' (rule 5710): a login attempt for an account that doesn't exist."""
    port = src_port if src_port is not None else pick_int(rng, 32768, 60999, "sport", asset.hostname, src_ip, iso_z(timestamp, digits=6))
    pid = _sshd_pid(rng, asset, timestamp, src_ip, port)
    return _sshd(
        org, asset, timestamp, rule_name="sshd_invalid_user",
        message=f"Invalid user {username} from {src_ip} port {port}",
        data={"srcip": src_ip, "srcport": str(port), "srcuser": username},
        pid=pid, simulation=simulation, rng=rng,
    )


def ssh_accepted_password(
    org: Org, asset: Asset, user: User, timestamp: datetime, *, src_ip: str, src_port: Optional[int] = None,
    simulation: Optional[dict] = None, rng: Optional[random.Random] = None,
) -> dict:
    """'Accepted password for <user> from <ip> port <n> ssh2' (rule 5715)."""
    port = src_port if src_port is not None else pick_int(rng, 32768, 60999, "sport", asset.hostname, src_ip, iso_z(timestamp, digits=6))
    pid = _sshd_pid(rng, asset, timestamp, src_ip, port)
    return _sshd(
        org, asset, timestamp, rule_name="sshd_auth_success",
        message=f"Accepted password for {user.username} from {src_ip} port {port} ssh2",
        data={"srcip": src_ip, "srcport": str(port), "dstuser": user.username},
        pid=pid, simulation=simulation, rng=rng,
    )


def sudo_command(
    org: Org, asset: Asset, user: User, timestamp: datetime, *, command: str, run_as: str = "root",
    tty: str = "pts/0", pwd: Optional[str] = None, simulation: Optional[dict] = None,
    rng: Optional[random.Random] = None,
) -> dict:
    """
    sudo's auth.log line (rule 5402 to root, 5407 otherwise). sudo logs
    through syslog without a PID on Ubuntu 22.04, so the line has none.
    """
    cwd = pwd or f"/home/{user.username}"
    message = f" {user.username} : TTY={tty} ; PWD={cwd} ; USER={run_as} ; COMMAND={command}"
    return alert(
        org, asset, timestamp, rule=RULES["sudo_to_root" if run_as == "root" else "sudo_executed"],
        decoder={"parent": "sudo", "name": "sudo", "ftscomment": "First time user executed the sudo command"},
        location=AUTH_LOG, full_log=syslog_line(org, asset, timestamp, "sudo", message),
        predecoder=predecoder(org, asset, timestamp, "sudo"),
        data={"srcuser": user.username, "tty": tty, "pwd": cwd, "dstuser": run_as, "command": command},
        simulation=simulation, rng=rng,
    )


def _audit_value(arg: str) -> Optional[str]:
    """
    How auditd writes one untrusted string: quoted, or as upper-case hex
    (no quotes) when it holds a space, a quote or a non-printable byte.
    Returns None for the hex case, which Wazuh's decoder doesn't extract.
    """
    if arg and all(0x21 <= ord(c) <= 0x7E and c != '"' for c in arg):
        return arg
    return None


def _audit_field(name: str, value: str) -> str:
    quoted = _audit_value(value)
    return f'{name}="{quoted}"' if quoted is not None else f"{name}={value.encode().hex().upper()}"


def auditd_execve(
    org: Org, asset: Asset, timestamp: datetime, *, exe: str, argv: list[str], user: str, uid: int, pid: int,
    ppid: int, cwd: str, auid: Optional[int] = None, tty: str = "pts0", session: Optional[int] = None,
    simulation: Optional[dict] = None, rng: Optional[random.Random] = None,
) -> dict:
    """
    One execve() as auditd logs it (SYSCALL, EXECVE, CWD, PATH, PROCTITLE
    records sharing one serial), alerted by stock rule 80792. Wazuh's
    audit log collector joins an event's records into one line, which is
    full_log. Records use auditd's default ENRICHED format, so the
    SYSCALL record ends with the resolved names (AUID="<user>" ...).

    `user` is the login user (the audit uid's name), `uid` the uid the
    command ran as (0 after sudo), `auid` the login uid (defaults to uid).
    """
    auid = uid if auid is None else auid
    gid = uid
    uid_name = "root" if uid == 0 else user
    ts_iso = iso_z(timestamp, digits=6)
    serial = pick_int(rng, 10_000, 9_999_999, "audit", asset.hostname, ts_iso, exe)
    session = session if session is not None else pick_int(rng, 1, 400, "ses", asset.hostname, user)
    inode = pick_int(rng, 100_000, 9_999_999, "inode", asset.hostname, exe)
    comm = exe.rsplit("/", 1)[-1][:15]  # the kernel's comm is the first 15 bytes of the file name
    stamp = f"msg=audit({int(timestamp.timestamp())}.{timestamp.microsecond // 1000:03d}:{serial}):"
    pointers = [f"{pick_int(rng, 0x55D000000000, 0x55DFFFFFFFFF, 'ptr', serial, i):x}" for i in range(3)]

    names = (f'AUID="{user}" UID="{uid_name}" GID="{uid_name}" EUID="{uid_name}" SUID="{uid_name}" '
             f'FSUID="{uid_name}" EGID="{uid_name}" SGID="{uid_name}" FSGID="{uid_name}"')
    records = [
        f"type=SYSCALL {stamp} arch=c000003e syscall=59 success=yes exit=0 a0={pointers[0]} a1={pointers[1]} "
        f"a2={pointers[2]} a3=0 items=2 ppid={ppid} pid={pid} auid={auid} uid={uid} gid={gid} euid={uid} "
        f"suid={uid} fsuid={uid} egid={gid} sgid={gid} fsgid={gid} tty={tty} ses={session} comm=\"{comm}\" "
        f'exe="{exe}" subj=unconfined key="{AUDIT_COMMAND_KEY}"{_ENRICHED_SEPARATOR}ARCH=x86_64 SYSCALL=execve {names}',
        f"type=EXECVE {stamp} argc={len(argv)} " + " ".join(_audit_field(f"a{i}", a) for i, a in enumerate(argv)),
        f"type=CWD {stamp} {_audit_field('cwd', cwd)}",
        f'type=PATH {stamp} item=0 name="{exe}" inode={inode} dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 '
        f"nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0{_ENRICHED_SEPARATOR}OUID=\"root\" OGID=\"root\"",
        f'type=PATH {stamp} item=1 name="/lib64/ld-linux-x86-64.so.2" inode=1835071 dev=fd:00 mode=0100755 ouid=0 '
        f"ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0"
        f'{_ENRICHED_SEPARATOR}OUID="root" OGID="root"',
        f"type=PROCTITLE {stamp} proctitle={chr(0).join(argv).encode().hex().upper()}",
    ]

    execve = {}
    for i, arg in enumerate(argv[:_DECODED_EXECVE_ARGS]):
        if _audit_value(arg) is not None:
            execve[f"a{i}"] = arg
    audit = {
        "type": "SYSCALL", "id": str(serial), "arch": "c000003e", "syscall": "59", "success": "yes", "exit": "0",
        "ppid": str(ppid), "pid": str(pid), "auid": str(auid), "uid": str(uid), "gid": str(gid), "euid": str(uid),
        "suid": str(uid), "fsuid": str(uid), "egid": str(gid), "sgid": str(gid), "fsgid": str(gid), "tty": tty,
        "session": str(session), "command": comm, "exe": exe, "key": AUDIT_COMMAND_KEY, "execve": execve,
        "file": {"name": exe, "inode": str(inode), "mode": "0100755"},
    }
    if _audit_value(cwd) is not None:
        audit["cwd"] = cwd
    return alert(
        org, asset, timestamp, rule=RULES["audit_command"], decoder={"name": "auditd"}, location=AUDIT_LOG,
        full_log=" ".join(records), data={"audit": audit}, description=f"Audit: Command: {exe}.",
        simulation=simulation, rng=rng,
    )
