"""
SafeSOC — Simulator Linux (sshd / sudo) Builders
Ubuntu auth.log lines wrapped as Wazuh alerts, with data.* fields as
Wazuh's sshd and sudo decoders extract them.
"""

from __future__ import annotations

import random
from datetime import datetime
from typing import Optional

from injector.sim.formats.wazuh_common import RULES, alert, iso_z, pick_int, predecoder, syslog_line
from injector.sim.org import Asset, Org, User

__all__ = ["ssh_failed_password", "ssh_invalid_user", "ssh_accepted_password", "sudo_command"]

AUTH_LOG = "/var/log/auth.log"


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
