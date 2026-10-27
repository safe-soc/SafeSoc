"""
SafeSOC — Simulator OpenVPN Builders
OpenVPN 2.6 server log lines (via syslog, `openvpn[pid]:`) as Wazuh
alerts, decoder openvpn. Line formats follow OpenVPN's own messages:
"<ip>:<port> TLS Auth Error: ...", "<ip>:<port> [<cn>] Peer Connection
Initiated with [AF_INET]<ip>:<port>", "<cn>/<ip>:<port> MULTI_sva: pool
returned IPv4=..." and "<cn>/<ip>:<port> SIGTERM[soft,remote-exit] ...".
"""

from __future__ import annotations

import random
from datetime import datetime
from typing import Optional

from injector.sim.formats.wazuh_common import RULES, alert, pick_int, predecoder, syslog_line
from injector.sim.org import Asset, Org, User

__all__ = ["auth_failed", "peer_connection_initiated", "client_address_assigned", "client_disconnected"]

SYSLOG = "/var/log/syslog"


def _pid(rng, asset: Asset) -> int:
    # One long-running server process: the same PID for every line from this host.
    return pick_int(rng, 700, 2000, "openvpn", asset.hostname)


def _openvpn(org, asset, ts, *, rule_name, message, data, simulation, rng) -> dict:
    return alert(
        org, asset, ts, rule=RULES[rule_name], decoder={"name": "openvpn"}, location=SYSLOG,
        full_log=syslog_line(org, asset, ts, "openvpn", message, _pid(rng, asset)),
        predecoder=predecoder(org, asset, ts, "openvpn"), data=data, simulation=simulation, rng=rng,
    )


def auth_failed(
    org: Org, asset: Asset, timestamp: datetime, *, src_ip: str, src_port: int, simulation: Optional[dict] = None,
    rng: Optional[random.Random] = None,
) -> dict:
    """
    Username/password rejected (custom rule 100400). OpenVPN does not
    print the attempted username on this line, so data has no user.
    """
    return _openvpn(
        org, asset, timestamp, rule_name="openvpn_auth_failed",
        message=f"{src_ip}:{src_port} TLS Auth Error: Auth Username/Password verification failed for peer",
        data={"srcip": src_ip, "srcport": str(src_port)}, simulation=simulation, rng=rng,
    )


def peer_connection_initiated(
    org: Org, asset: Asset, user: User, timestamp: datetime, *, src_ip: str, src_port: int,
    simulation: Optional[dict] = None, rng: Optional[random.Random] = None,
) -> dict:
    """Successful login (stock rule 81801 'OpenVPN: User logged in')."""
    return _openvpn(
        org, asset, timestamp, rule_name="openvpn_login",
        message=f"{src_ip}:{src_port} [{user.username}] Peer Connection Initiated with [AF_INET]{src_ip}:{src_port}",
        data={"srcip": src_ip, "srcport": str(src_port), "srcuser": user.username}, simulation=simulation, rng=rng,
    )


def client_address_assigned(
    org: Org, asset: Asset, user: User, timestamp: datetime, *, src_ip: str, src_port: int, virtual_ip: str,
    simulation: Optional[dict] = None, rng: Optional[random.Random] = None,
) -> dict:
    """The client's real address and the virtual (tunnel) address handed out from the pool (custom rule 100401)."""
    return _openvpn(
        org, asset, timestamp, rule_name="openvpn_address_assigned",
        message=f"{user.username}/{src_ip}:{src_port} MULTI_sva: pool returned IPv4={virtual_ip}, IPv6=(Not enabled)",
        data={"srcip": src_ip, "srcport": str(src_port), "srcuser": user.username, "virtual_ip": virtual_ip},
        simulation=simulation, rng=rng,
    )


def client_disconnected(
    org: Org, asset: Asset, user: User, timestamp: datetime, *, src_ip: str, src_port: int,
    simulation: Optional[dict] = None, rng: Optional[random.Random] = None,
) -> dict:
    """Client-initiated disconnect (custom rule 100402)."""
    return _openvpn(
        org, asset, timestamp, rule_name="openvpn_disconnected",
        message=f"{user.username}/{src_ip}:{src_port} SIGTERM[soft,remote-exit] received, client-instance exiting",
        data={"srcip": src_ip, "srcport": str(src_port), "srcuser": user.username}, simulation=simulation, rng=rng,
    )
