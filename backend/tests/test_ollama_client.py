"""
SafeSOC — Ollama Client Tests
"""

from unittest.mock import Mock

import pytest
import requests

from app.clients import ollama


def _fake_response(text: str) -> Mock:
    response = Mock()
    response.raise_for_status = Mock()
    response.json.return_value = {"model": "mistral:7b", "response": text, "done": True}
    return response


def test_generate_returns_the_completion_text(monkeypatch):
    monkeypatch.setattr(ollama.requests, "post", Mock(return_value=_fake_response("Here are the failed logins.")))

    result = ollama.generate("Show me failed logins for host DESKTOP-042")

    assert result == "Here are the failed logins."


def test_generate_sends_the_configured_model_and_prompt(monkeypatch):
    mock_post = Mock(return_value=_fake_response("ok"))
    monkeypatch.setattr(ollama.requests, "post", mock_post)
    monkeypatch.setattr(ollama.settings, "OLLAMA_MODEL", "mistral:7b")

    ollama.generate("what happened on DESKTOP-042?")

    _, kwargs = mock_post.call_args
    assert kwargs["json"]["model"] == "mistral:7b"
    assert kwargs["json"]["prompt"] == "what happened on DESKTOP-042?"
    assert kwargs["json"]["stream"] is False


def test_connection_failure_raises_typed_exception_not_requests_exception(monkeypatch):
    def _raise(*args, **kwargs):
        raise requests.exceptions.ConnectionError("connection refused")

    monkeypatch.setattr(ollama.requests, "post", _raise)

    with pytest.raises(ollama.OllamaError):
        ollama.generate("anything")


def test_http_error_status_raises_typed_exception(monkeypatch):
    response = Mock()
    response.raise_for_status.side_effect = requests.exceptions.HTTPError("500 Internal Server Error")
    monkeypatch.setattr(ollama.requests, "post", Mock(return_value=response))

    with pytest.raises(ollama.OllamaError):
        ollama.generate("anything")


def test_missing_response_field_returns_empty_string_gracefully(monkeypatch):
    response = Mock()
    response.raise_for_status = Mock()
    response.json.return_value = {"model": "mistral:7b", "done": True}
    monkeypatch.setattr(ollama.requests, "post", Mock(return_value=response))

    assert ollama.generate("anything") == ""
