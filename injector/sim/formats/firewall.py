"""
SafeSOC — Simulator Firewall / IDS Builders
pfSense 2.7 filterlog CSV lines (decoder pf) and Suricata EVE alert
records (decoder json), both from EB-FW01, as Wazuh alerts.
"""

from __future__ import annotations

import random
from datetime import datetime
from typing import Literal, Optional

from injector.sim.formats.wazuh_common import RULES, alert, iso_z, local_time, pick_int, predecoder, syslog_line
from injector.sim.org import Asset, Org

__all__ = ["filterlog", "suricata_alert"]

FILTER_LOG = "/var/log/filter.log"
EVE_JSON = "/var/log/suricata/eve.json"
WAN_INTERFACE = "igb0"
_PROTO_IDS = {"tcp": 6, "udp": 17, "icmp": 1}


def filterlog(
    org: Org, firewall: Asset, timestamp: datetime, *, action: Literal["block", "pass"], src_ip: str, dst_ip: str,
    proto: Literal["tcp", "udp"] = "tcp", src_port: int, dst_port: int, interface: str = WAN_INTERFACE,
    direction: Literal["in", "out"] = "in", rule_number: int = 5, tracker: str = "1000000103",
    tcp_flags: str = "S", simulation: Optional[dict] = None, rng: Optional[random.Random] = None,
) -> dict:
    """
    One IPv4 filterlog entry: rule, sub-rule, anchor, tracker, interface,
    reason, action, direction, ip version, tos, ecn, ttl, id, offset,
    flags, proto id, proto, length, src, dst, then the TCP or UDP fields.
    Blocks fire stock rule 87701; passes have no stock alert (custom 100700).
    """
    seed = (firewall.hostname, src_ip, dst_ip, src_port, dst_port, iso_z(timestamp, digits=6))
    ip_id = pick_int(rng, 1, 65535, "ipid", *seed)
    ttl = pick_int(rng, 40, 128, "ttl", *seed)
    if proto == "tcp":
        seq = pick_int(rng, 1, 4_294_967_295, "seq", *seed)
        transport = f"{src_port},{dst_port},0,{tcp_flags},{seq},,64240,,mss;sackOK;TS;nop;wscale"
        length = 60
    else:
        transport = f"{src_port},{dst_port},40"
        length = 68
    csv = (
        f"{rule_number},,,{tracker},{interface},match,{action},{direction},4,0x0,,{ttl},{ip_id},0,DF,"
        f"{_PROTO_IDS[proto]},{proto},{length},{src_ip},{dst_ip},{transport}"
    )
    pid = pick_int(rng, 10000, 99999, "filterlog", firewall.hostname)
    return alert(
        org, firewall, timestamp, rule=RULES["pf_block" if action == "block" else "pf_pass"], decoder={"name": "pf"},
        location=FILTER_LOG, full_log=syslog_line(org, firewall, timestamp, "filterlog", csv, pid),
        predecoder=predecoder(org, firewall, timestamp, "filterlog"),
        data={"action": action, "protocol": proto, "srcip": src_ip, "dstip": dst_ip,
              "srcport": str(src_port), "dstport": str(dst_port)},
        simulation=simulation, rng=rng,
    )


def suricata_alert(
    org: Org, firewall: Asset, timestamp: datetime, *, src_ip: str, src_port: int, dest_ip: str, dest_port: int,
    proto: str = "TCP", signature: str, signature_id: int, category: str, severity: int = 2, rev: int = 1,
    gid: int = 1, action: Literal["allowed", "blocked"] = "allowed", in_iface: str = WAN_INTERFACE,
    app_proto: Optional[str] = None, simulation: Optional[dict] = None, rng: Optional[random.Random] = None,
) -> dict:
    """
    One EVE `alert` record (stock rule 86601, level 3 for every
    signature: the rule has no_full_log, so there is no full_log).
    Signatures and SIDs are the caller's: use real ET Open ones.
    """
    local = local_time(org, timestamp)
    eve = {
        "timestamp": local.strftime("%Y-%m-%dT%H:%M:%S.") + f"{local.microsecond:06d}" + local.strftime("%z"),
        "flow_id": str(pick_int(rng, 10**14, 10**16 - 1, "flow", firewall.hostname, src_ip, src_port, dest_ip, dest_port)),
        "in_iface": in_iface,
        "event_type": "alert",
        "src_ip": src_ip,
        "src_port": str(src_port),
        "dest_ip": dest_ip,
        "dest_port": str(dest_port),
        "proto": proto,
        "alert": {
            "action": action,
            "gid": str(gid),
            "signature_id": str(signature_id),
            "rev": str(rev),
            "signature": signature,
            "category": category,
            "severity": str(severity),
        },
    }
    if app_proto:
        eve["app_proto"] = app_proto
    return alert(
        org, firewall, timestamp, rule=RULES["suricata_alert"], decoder={"name": "json"}, location=EVE_JSON,
        data=eve, description=f"Suricata: Alert - {signature}", simulation=simulation, rng=rng,
    )
