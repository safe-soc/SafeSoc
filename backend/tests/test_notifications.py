"""
SafeSOC — Notification Service Tests (SS-056)
"""

from unittest.mock import Mock

from app.core.enums import CorrelationPattern
from app.services import notifications
from app.services.correlation import DetectedChain


def _critical_alert(**overrides) -> dict:
    base = {
        "alert_id": "a1b2c3",
        "host_id": "DESKTOP-042",
        "action": "failed_login",
        "description": "Multiple failed SSH attempts",
        "severity": "critical",
    }
    base.update(overrides)
    return base


def _chain(**overrides) -> DetectedChain:
    base = dict(
        pattern=CorrelationPattern.CREDENTIAL_BRUTE_FORCE,
        confidence=0.85,
        alert_ids=("a1", "a2", "a3"),
        mitre_technique_ids=("T1110",),
        mitre_tactic="Credential Access",
    )
    base.update(overrides)
    return DetectedChain(**base)


# ── format_critical_alert_message ───────────────────────────────

def test_format_critical_alert_message_includes_key_fields():
    message = notifications.format_critical_alert_message(_critical_alert())

    assert "DESKTOP-042" in message
    assert "failed_login" in message
    assert "Multiple failed SSH attempts" in message
    assert "a1b2c3" in message


# ── notify_critical_alert ───────────────────────────────────────

def test_notify_critical_alert_sends_for_critical_severity(monkeypatch):
    mock_send = Mock(return_value=True)
    monkeypatch.setattr(notifications.telegram, "send_message", mock_send)

    result = notifications.notify_critical_alert(_critical_alert())

    assert result is True
    mock_send.assert_called_once()


def test_notify_critical_alert_is_a_no_op_for_non_critical_severity(monkeypatch):
    mock_send = Mock()
    monkeypatch.setattr(notifications.telegram, "send_message", mock_send)

    result = notifications.notify_critical_alert(_critical_alert(severity="high"))

    assert result is False
    mock_send.assert_not_called()


def test_notify_critical_alert_returns_false_when_telegram_is_not_configured(monkeypatch):
    """Propagates telegram.send_message's own graceful skip (SS-055) rather than masking it."""
    monkeypatch.setattr(notifications.telegram, "send_message", Mock(return_value=False))

    assert notifications.notify_critical_alert(_critical_alert()) is False


# ── format_attack_chain_message ──────────────────────────────────

def test_format_attack_chain_message_includes_key_fields():
    chain = _chain()
    message = notifications.format_attack_chain_message("DESKTOP-042", chain, "incident-123")

    assert "DESKTOP-042" in message
    assert "Credential Brute Force" in message
    assert "85%" in message
    assert "Credential Access" in message
    assert "incident-123" in message


# ── notify_attack_chain ──────────────────────────────────────────

def test_notify_attack_chain_sends_a_message(monkeypatch):
    mock_send = Mock(return_value=True)
    monkeypatch.setattr(notifications.telegram, "send_message", mock_send)

    result = notifications.notify_attack_chain("DESKTOP-042", _chain(), "incident-123")

    assert result is True
    mock_send.assert_called_once()
    (message,), _kwargs = mock_send.call_args
    assert "DESKTOP-042" in message
