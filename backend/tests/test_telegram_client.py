"""
SafeSOC — Telegram Client Tests (SS-055)
"""

from unittest.mock import Mock

import pytest
import requests

from app.clients import telegram


def _fake_response() -> Mock:
    response = Mock()
    response.raise_for_status = Mock()
    return response


def _configure(monkeypatch, token="test-token", chat_id="12345"):
    monkeypatch.setattr(telegram.settings, "TELEGRAM_BOT_TOKEN", token)
    monkeypatch.setattr(telegram.settings, "TELEGRAM_CHAT_ID", chat_id)


def test_send_message_skips_without_erroring_when_bot_token_is_missing(monkeypatch):
    """AC: missing configuration skips sending without erroring."""
    _configure(monkeypatch, token="", chat_id="12345")
    mock_post = Mock()
    monkeypatch.setattr(telegram.requests, "post", mock_post)

    result = telegram.send_message("Critical alert on DESKTOP-042")

    assert result is False
    mock_post.assert_not_called()


def test_send_message_skips_without_erroring_when_chat_id_is_missing(monkeypatch):
    _configure(monkeypatch, token="test-token", chat_id="")
    mock_post = Mock()
    monkeypatch.setattr(telegram.requests, "post", mock_post)

    result = telegram.send_message("Critical alert on DESKTOP-042")

    assert result is False
    mock_post.assert_not_called()


def test_send_message_returns_true_on_a_confirmed_send(monkeypatch):
    _configure(monkeypatch)
    monkeypatch.setattr(telegram.requests, "post", Mock(return_value=_fake_response()))

    assert telegram.send_message("Critical alert on DESKTOP-042") is True


def test_send_message_posts_to_the_configured_bot_and_chat(monkeypatch):
    _configure(monkeypatch, token="abc123", chat_id="98765")
    mock_post = Mock(return_value=_fake_response())
    monkeypatch.setattr(telegram.requests, "post", mock_post)

    telegram.send_message("Critical alert on DESKTOP-042")

    args, kwargs = mock_post.call_args
    assert args[0] == "https://api.telegram.org/botabc123/sendMessage"
    assert kwargs["json"]["chat_id"] == "98765"
    assert kwargs["json"]["text"] == "Critical alert on DESKTOP-042"


def test_send_message_raises_a_typed_exception_on_connection_failure(monkeypatch):
    _configure(monkeypatch)

    def _raise(*args, **kwargs):
        raise requests.exceptions.ConnectionError("connection refused")

    monkeypatch.setattr(telegram.requests, "post", _raise)

    with pytest.raises(telegram.TelegramError):
        telegram.send_message("anything")


def test_send_message_raises_a_typed_exception_on_an_error_response(monkeypatch):
    _configure(monkeypatch)
    response = Mock()
    response.raise_for_status.side_effect = requests.exceptions.HTTPError("400 Bad Request")
    monkeypatch.setattr(telegram.requests, "post", Mock(return_value=response))

    with pytest.raises(telegram.TelegramError):
        telegram.send_message("anything")
