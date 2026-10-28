"""
SafeSOC — Simulator Web (nginx access log) Builder
One nginx "combined" access-log line as a Wazuh alert (decoder
web-accesslog), with the rule Wazuh's web ruleset picks for it.
"""

from __future__ import annotations

import random
from datetime import datetime
from typing import Literal, Optional

from injector.sim.formats.wazuh_common import RULES, alert, local_time
from injector.sim.org import Asset, Org

__all__ = ["access_log"]

ACCESS_LOG = "/var/log/nginx/access.log"
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)

Attack = Literal["sql_injection", "xss", "common"]
_ATTACK_RULES = {"sql_injection": "web_sql_injection", "xss": "web_xss", "common": "web_common_attack"}


def _rule_name(status: int, attack: Optional[Attack]) -> str:
    # Wazuh's attack rules match on the URL; when the server answered 200
    # the child rule 31106 ("A web attack returned code 200") fires instead.
    if attack:
        return "web_attack_success" if status == 200 else _ATTACK_RULES[attack]
    if 400 <= status < 500:
        return "web_400"
    if status == 500:
        return "web_500"
    if 500 < status < 600:
        return "web_5xx"
    return "web_request"


def access_log(
    org: Org, asset: Asset, timestamp: datetime, *, src_ip: str, method: str = "GET", url: str = "/",
    status: int = 200, body_bytes: int = 0, referer: str = "-", user_agent: str = DEFAULT_USER_AGENT,
    protocol: str = "HTTP/1.1", attack: Optional[Attack] = None, simulation: Optional[dict] = None,
    rng: Optional[random.Random] = None,
) -> dict:
    """
    `attack` is the caller's statement of what the URL contains (Wazuh
    detects it by URL pattern); it selects the matching stock rule.
    """
    local = local_time(org, timestamp)
    stamp = local.strftime("%d/%b/%Y:%H:%M:%S %z")
    line = f'{src_ip} - - [{stamp}] "{method} {url} {protocol}" {status} {body_bytes} "{referer}" "{user_agent}"'
    return alert(
        org, asset, timestamp, rule=RULES[_rule_name(status, attack)], decoder={"name": "web-accesslog"},
        location=ACCESS_LOG, full_log=line,
        data={"protocol": method, "srcip": src_ip, "id": str(status), "url": url},
        simulation=simulation, rng=rng,
    )
