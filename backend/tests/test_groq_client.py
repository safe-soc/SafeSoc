"""
SafeSOC — Groq Client Tests
"""

from unittest.mock import Mock

import pytest
import requests

from app.clients import groq


def _fake_response(text: str) -> Mock:
    response = Mock()
    response.raise_for_status = Mock()
    response.json.return_value = {"choices": [{"message": {"content": text, "role": "assistant"}}]}
    return response


def test_generate_returns_the_completion_text(monkeypatch):
    monkeypatch.setattr(groq.requests, "post", Mock(return_value=_fake_response("Here are the failed logins.")))

    result = groq.generate("Show me failed logins for host DESKTOP-042")

    assert result == "Here are the failed logins."


def test_generate_sends_the_configured_model_and_prompt_as_a_chat_message(monkeypatch):
    mock_post = Mock(return_value=_fake_response("ok"))
    monkeypatch.setattr(groq.requests, "post", mock_post)
    monkeypatch.setattr(groq.settings, "GROQ_MODEL", "mixtral-8x7b-32768")
    monkeypatch.setattr(groq.settings, "GROQ_API_KEY", "test-key")

    groq.generate("what happened on DESKTOP-042?")

    args, kwargs = mock_post.call_args
    assert kwargs["json"]["model"] == "mixtral-8x7b-32768"
    assert kwargs["json"]["messages"] == [{"role": "user", "content": "what happened on DESKTOP-042?"}]
    assert kwargs["headers"]["Authorization"] == "Bearer test-key"


def test_generate_caps_output_tokens_at_the_configured_limit(monkeypatch):
    """Same bound as ollama.py's num_predict, for provider parity (latency diagnosis)."""
    mock_post = Mock(return_value=_fake_response("ok"))
    monkeypatch.setattr(groq.requests, "post", mock_post)
    monkeypatch.setattr(groq.settings, "INVESTIGATION_LLM_MAX_OUTPUT_TOKENS", 120)

    groq.generate("anything")

    assert mock_post.call_args.kwargs["json"]["max_tokens"] == 120


def test_connection_failure_raises_typed_exception_not_requests_exception(monkeypatch):
    def _raise(*args, **kwargs):
        raise requests.exceptions.ConnectionError("connection refused")

    monkeypatch.setattr(groq.requests, "post", _raise)

    with pytest.raises(groq.GroqError):
        groq.generate("anything")


def test_http_error_status_raises_typed_exception(monkeypatch):
    response = Mock()
    response.raise_for_status.side_effect = requests.exceptions.HTTPError("401 Unauthorized")
    monkeypatch.setattr(groq.requests, "post", Mock(return_value=response))

    with pytest.raises(groq.GroqError):
        groq.generate("anything")


def test_unexpected_response_shape_raises_typed_exception(monkeypatch):
    response = Mock()
    response.raise_for_status = Mock()
    response.json.return_value = {"choices": []}
    monkeypatch.setattr(groq.requests, "post", Mock(return_value=response))

    with pytest.raises(groq.GroqError):
        groq.generate("anything")


def test_same_interface_contract_as_ollama_client():
    """SS-043's own AC: same interface contract as SS-042, selectable via settings.LLM_PROVIDER."""
    from app.clients import ollama

    assert callable(groq.generate)
    import inspect
    assert inspect.signature(groq.generate) == inspect.signature(ollama.generate)
