"""
SafeSOC — Telegram Client
SafeSOC's own Telegram notifier (SS-055), structurally similar to
CloudLens's engine/notifier.py (cloud/AWS-IAM-backend) but independent
— different stack, different message content (SafeSOC alerts/incidents,
not IAM findings), no shared code between the two codebases.

Missing configuration skips sending silently rather than raising,
matching CloudLens's own graceful-degradation behavior (AC): a SOC
whose Telegram bot isn't configured yet shouldn't have that break
whatever's asking it to notify (SS-056).
"""

import requests

from app.core.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)

TELEGRAM_API_BASE = "https://api.telegram.org"


class TelegramError(Exception):
    """Raised when Telegram is reachable but the send itself fails (network error or non-2xx response)."""


def send_message(text: str) -> bool:
    """
    Send a Markdown-formatted message to the configured chat.

    Returns False (does not raise) if TELEGRAM_BOT_TOKEN or
    TELEGRAM_CHAT_ID isn't configured — skipped, not an error (AC).
    Returns True once Telegram has confirmed the send.

    Raises:
        TelegramError: if configuration is present but the request
        itself fails — a genuine send failure, not "not configured."
    """
    if not settings.TELEGRAM_BOT_TOKEN or not settings.TELEGRAM_CHAT_ID:
        logger.info("Telegram not configured, skipping notification")
        return False

    url = f"{TELEGRAM_API_BASE}/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": settings.TELEGRAM_CHAT_ID, "text": text, "parse_mode": "Markdown"}

    try:
        response = requests.post(url, json=payload, timeout=8)
        response.raise_for_status()
    except requests.RequestException as e:
        raise TelegramError(f"Telegram request failed: {e}") from e

    return True
