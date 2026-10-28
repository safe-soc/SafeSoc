"""
SafeSOC — Simulator Mail Gateway Builders
EB-MAIL01 (Postfix + content filter) log lines for an inbound message,
as Wazuh alerts on custom rules:

- attachment_warning: Postfix cleanup's mime_header_checks WARN line
  for the attachment's Content-Type header (name + MIME type).
- content_filter_verdict: the content filter's per-message verdict
  line (amavis-style: Passed/Blocked <VERDICT>, sender, recipient,
  Queue-ID, Message-ID, Subject).
"""

from __future__ import annotations

import random
from datetime import datetime
from typing import Optional

from injector.sim.formats.wazuh_common import RULES, alert, iso_z, pick_int, predecoder, stable_hex, syslog_line
from injector.sim.org import Asset, Org

__all__ = ["attachment_warning", "content_filter_verdict"]

MAIL_LOG = "/var/log/mail.log"
BLOCKING_VERDICTS = {"SPAM", "BANNED", "INFECTED"}


def queue_id(*seed) -> str:
    """A Postfix long queue ID-shaped token, stable for the same seed (pass the same seed to tie lines together)."""
    return stable_hex("queue", *seed, length=12).upper()


def attachment_warning(
    org: Org, mail: Asset, timestamp: datetime, *, client_ip: str, client_helo: str, sender: str, recipient: str,
    attachment_name: str, mime_type: str, queue: str, simulation: Optional[dict] = None,
    rng: Optional[random.Random] = None,
) -> dict:
    """postfix/cleanup: 'warning: header Content-Type: <mime>; name="<file>" from unknown[<ip>]; from=<..> to=<..> ...'."""
    message = (
        f'{queue}: warning: header Content-Type: {mime_type}; name="{attachment_name}" from unknown[{client_ip}]; '
        f"from=<{sender}> to=<{recipient}> proto=ESMTP helo=<{client_helo}>"
    )
    pid = pick_int(rng, 1000, 65000, "cleanup", mail.hostname, iso_z(timestamp, digits=6))
    return alert(
        org, mail, timestamp, rule=RULES["mail_attachment"], decoder={"parent": "postfix", "name": "postfix-warning"},
        location=MAIL_LOG, full_log=syslog_line(org, mail, timestamp, "postfix/cleanup", message, pid),
        predecoder=predecoder(org, mail, timestamp, "postfix/cleanup"),
        data={"srcip": client_ip, "from": sender, "to": recipient, "attachment": attachment_name,
              "mime_type": mime_type, "queue_id": queue},
        simulation=simulation, rng=rng,
    )


def content_filter_verdict(
    org: Org, mail: Asset, timestamp: datetime, *, client_ip: str, client_port: int, sender: str, recipient: str,
    subject: str, verdict: str, queue: str, message_id: str, size: int, hits: float = 0.0,
    simulation: Optional[dict] = None, rng: Optional[random.Random] = None,
) -> dict:
    """The filter's verdict for one message: CLEAN/SPAMMY pass (100501), SPAM/BANNED/INFECTED block (100502)."""
    verdict = verdict.upper()
    blocked = verdict in BLOCKING_VERDICTS
    pid = pick_int(rng, 1000, 65000, "amavis", mail.hostname)
    task = f"({pid:05d}-{pick_int(rng, 1, 99, 'task', queue):02d})"
    outcome = "Blocked" if blocked else "Passed"
    elapsed = pick_int(rng, 300, 4000, "elapsed", queue)
    message = (
        f"{task} {outcome} {verdict} {{{'DiscardedInbound' if blocked else 'RelayedInbound'}}}, "
        f"[{client_ip}]:{client_port} <{sender}> -> <{recipient}>, Queue-ID: {queue}, Message-ID: <{message_id}>, "
        f"Hits: {hits:.3f}, size: {size}, Subject: \"{subject}\", {elapsed} ms"
    )
    return alert(
        org, mail, timestamp, rule=RULES["mail_filter_blocked" if blocked else "mail_filter_passed"],
        decoder={"name": "amavis"}, location=MAIL_LOG,
        full_log=syslog_line(org, mail, timestamp, "amavis", message, pid),
        predecoder=predecoder(org, mail, timestamp, "amavis"),
        data={"srcip": client_ip, "srcport": str(client_port), "from": sender, "to": recipient, "subject": subject,
              "verdict": verdict, "action": outcome.lower(), "queue_id": queue, "message_id": message_id},
        simulation=simulation, rng=rng,
    )
