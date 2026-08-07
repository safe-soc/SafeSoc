"""
SafeSOC — Notification Service
Builds and sends real-time notifications for critical-severity alerts
and newly-detected attack chains (SRS §3.2: "SMB IT Administrator...
receives immediate notification of critical events"), via the
Telegram client (SS-055). Message formatting is separated from
sending so it's testable without a configured bot (AC parity with
SS-050's "testable in isolation from the model" precedent).
"""

from app.clients import telegram
from app.services.correlation import DetectedChain


def format_critical_alert_message(alert: dict) -> str:
    return (
        "\U0001F534 *Critical Alert*\n"
        f"Host: `{alert.get('host_id', 'unknown')}`\n"
        f"Action: {alert.get('action', 'unknown')}\n"
        f"Description: {alert.get('description', '')}\n"
        f"Alert ID: `{alert.get('alert_id', '')}`"
    )


def notify_critical_alert(alert: dict) -> bool:
    """
    Send a Telegram notification for a critical-severity alert.

    No-op (returns False, doesn't call Telegram at all) for anything
    below critical severity — most alerts don't warrant paging someone
    immediately. The severity check lives here, not in the calling
    worker, matching how services/enrichment.py's own gating (nothing
    to enrich -> no-op) lives in the service rather than its worker.
    """
    if alert.get("severity") != "critical":
        return False

    return telegram.send_message(format_critical_alert_message(alert))


def format_attack_chain_message(host_id: str, chain: DetectedChain, incident_id) -> str:
    pattern_label = chain.pattern.value.replace("_", " ").title()
    return (
        f"\U0001F6A8 *Attack Chain Detected: {pattern_label}*\n"
        f"Host: `{host_id}`\n"
        f"Confidence: {chain.confidence:.0%}\n"
        f"MITRE Tactic: {chain.mitre_tactic}\n"
        f"Alerts involved: {len(chain.alert_ids)}\n"
        f"Incident: `{incident_id}`"
    )


def notify_attack_chain(host_id: str, chain: DetectedChain, incident_id) -> bool:
    """Send a Telegram notification for a detected attack chain (SS-031)."""
    return telegram.send_message(format_attack_chain_message(host_id, chain, incident_id))
