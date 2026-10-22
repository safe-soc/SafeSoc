"""
SafeSOC — Groq Client Tests
"""

from unittest.mock import Mock

import pytest
import requests

from app.clients import groq


@pytest.fixture(autouse=True)
def _configured_non_reasoning_model(monkeypatch):
    """
    A key and a plain (non-reasoning) model for every test here, so the
    max_tokens assertions keep exercising the non-gpt-oss branch of
    build_payload after the GROQ_MODEL default moved to a reasoning
    model. Tests that care about the key or the model override it.
    """
    monkeypatch.setattr(groq.settings, "GROQ_API_KEY", "test-key")
    monkeypatch.setattr(groq.settings, "GROQ_MODEL", "llama-3.1-8b-instant")


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


def test_generate_accepts_an_explicit_max_output_tokens_override(monkeypatch):
    """Same override contract as clients/ollama.py's generate() — see that test for why."""
    mock_post = Mock(return_value=_fake_response("ok"))
    monkeypatch.setattr(groq.requests, "post", mock_post)
    monkeypatch.setattr(groq.settings, "INVESTIGATION_LLM_MAX_OUTPUT_TOKENS", 120)

    groq.generate("anything", max_output_tokens=350)

    assert mock_post.call_args.kwargs["json"]["max_tokens"] == 350


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


# ── Misconfiguration and empty completions ───────────────────────────

def test_a_missing_api_key_raises_without_making_a_request(monkeypatch):
    """LLM_PROVIDER=groq with no key is the common misconfiguration — don't spend a round trip on a guaranteed 401."""
    mock_post = Mock()
    monkeypatch.setattr(groq.requests, "post", mock_post)
    monkeypatch.setattr(groq.settings, "GROQ_API_KEY", "")

    with pytest.raises(groq.GroqError):
        groq.generate("anything")

    mock_post.assert_not_called()


@pytest.mark.parametrize("content", ["", "   ", "\n\n", None])
def test_an_empty_completion_raises_so_the_caller_falls_back_to_its_template(content, monkeypatch):
    """A reasoning model that spends its whole budget thinking answers with nothing — never render that as the summary."""
    monkeypatch.setattr(groq.requests, "post", Mock(return_value=_fake_response(content)))

    with pytest.raises(groq.GroqError):
        groq.generate("anything")


# ── Reasoning (gpt-oss) models ───────────────────────────────────────

def test_a_gpt_oss_model_gets_reasoning_parameters_and_no_max_tokens(monkeypatch):
    mock_post = Mock(return_value=_fake_response("ok"))
    monkeypatch.setattr(groq.requests, "post", mock_post)
    monkeypatch.setattr(groq.settings, "GROQ_MODEL", "openai/gpt-oss-120b")
    monkeypatch.setattr(groq.settings, "GROQ_REASONING_EFFORT", "low")
    monkeypatch.setattr(groq.settings, "GROQ_REASONING_TOKEN_HEADROOM", 512)

    groq.generate("anything", max_output_tokens=120)

    payload = mock_post.call_args.kwargs["json"]
    assert payload["reasoning_effort"] == "low"
    assert payload["include_reasoning"] is False
    # The answer budget plus room for the thinking that precedes it.
    assert payload["max_completion_tokens"] == 120 + 512
    assert "max_tokens" not in payload
    # Unsupported for gpt-oss, and mutually exclusive with include_reasoning.
    assert "reasoning_format" not in payload


def test_the_smaller_gpt_oss_model_takes_the_same_reasoning_path(monkeypatch):
    monkeypatch.setattr(groq.settings, "GROQ_MODEL", "openai/gpt-oss-20b")

    payload = groq.build_payload("anything", 350)

    assert "max_completion_tokens" in payload
    assert "max_tokens" not in payload


def test_a_non_reasoning_model_keeps_the_plain_max_tokens_bound():
    payload = groq.build_payload("anything", 350)

    assert payload["max_tokens"] == 350
    assert "max_completion_tokens" not in payload
    assert "reasoning_effort" not in payload


def test_the_configured_default_model_is_not_a_retired_groq_model():
    """
    A request for a retired model id is a hard error, not a fallback —
    these three were all shut down (2025-03-20 / 2026-08-16) and must
    never be the shipped default again.
    """
    from app.core.config import Settings

    retired = {"mixtral-8x7b-32768", "llama-3.3-70b-versatile", "llama-3.1-8b-instant"}

    # The shipped field default, not an instantiated Settings() — this
    # must hold regardless of what a local .env happens to set.
    assert Settings.model_fields["GROQ_MODEL"].default not in retired


def test_same_interface_contract_as_ollama_client():
    """SS-043's own AC: same interface contract as SS-042, selectable via settings.LLM_PROVIDER."""
    from app.clients import ollama

    assert callable(groq.generate)
    import inspect
    assert inspect.signature(groq.generate) == inspect.signature(ollama.generate)
