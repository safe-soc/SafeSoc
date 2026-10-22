"""
SafeSOC — Groq Client
Cloud-based LLM completion via Groq's OpenAI-compatible chat
completions API, the fallback path when settings.LLM_PROVIDER == "groq"
(SS-043). Same interface contract as clients/ollama.py (SS-042):
generate(prompt, max_output_tokens=None) -> str, so callers can select
a provider without caring which one is active.
"""

from typing import Optional

import requests

from app.core.config import settings

GROQ_BASE_URL = "https://api.groq.com/openai/v1"


class GroqError(Exception):
    """Raised when Groq is unreachable or returns an error."""


# Groq's gpt-oss models are reasoning models and take a different
# parameter set from the plain chat models (see settings.GROQ_MODEL).
_REASONING_MODEL_PREFIX = "openai/gpt-oss"


def build_payload(prompt: str, max_output_tokens: int) -> dict:
    """
    The request body for settings.GROQ_MODEL, which differs by model
    family.

    For gpt-oss (reasoning) models the thinking tokens are drawn from
    the same completion budget as the answer, so sending the caller's
    budget as-is returns an empty completion whenever reasoning fills
    it — GROQ_REASONING_TOKEN_HEADROOM is added on top, and
    reasoning_effort keeps the thinking short. These models take
    max_completion_tokens, not max_tokens. include_reasoning=False
    keeps the thinking out of the response; reasoning_format is NOT
    sent — gpt-oss doesn't support it and it can't be combined with
    include_reasoning.

    Every other model keeps the original max_tokens bound, the same
    bound as ollama.py's num_predict (provider parity for latency
    diagnosis).
    """
    payload = {
        "model": settings.GROQ_MODEL,
        "messages": [{"role": "user", "content": prompt}],
    }
    if settings.GROQ_MODEL.startswith(_REASONING_MODEL_PREFIX):
        payload["reasoning_effort"] = settings.GROQ_REASONING_EFFORT
        payload["include_reasoning"] = False
        payload["max_completion_tokens"] = max_output_tokens + settings.GROQ_REASONING_TOKEN_HEADROOM
    else:
        payload["max_tokens"] = max_output_tokens
    return payload


def generate(prompt: str, max_output_tokens: Optional[int] = None) -> str:
    """
    Send a prompt to Groq's chat completions API and return the
    completion text.

    max_output_tokens defaults to settings.INVESTIGATION_LLM_MAX_OUTPUT_TOKENS
    when omitted — see clients/ollama.py's generate() for why callers
    with a different latency budget pass their own value instead.

    Raises:
        GroqError: if no API key is configured, or if Groq is
        unreachable, times out, returns an error response, or returns an
        empty completion.
    """
    if max_output_tokens is None:
        max_output_tokens = settings.INVESTIGATION_LLM_MAX_OUTPUT_TOKENS
    # Fail before the request rather than spending a round trip on a
    # guaranteed 401 — LLM_PROVIDER=groq with no key configured is the
    # common misconfiguration, and callers fall back to their template
    # on GroqError either way.
    if not settings.GROQ_API_KEY:
        raise GroqError("No GROQ_API_KEY is configured — set it, or set LLM_PROVIDER=ollama.")
    try:
        response = requests.post(
            f"{GROQ_BASE_URL}/chat/completions",
            headers={"Authorization": f"Bearer {settings.GROQ_API_KEY}"},
            json=build_payload(prompt, max_output_tokens),
            timeout=60,
        )
        response.raise_for_status()
    except requests.RequestException as e:
        raise GroqError(f"Groq request failed: {e}") from e

    try:
        content = response.json()["choices"][0]["message"]["content"]
    except (KeyError, IndexError) as e:
        raise GroqError(f"Groq returned an unexpected response shape: {e}") from e

    # A reasoning model that spends its whole budget thinking answers
    # with an empty string. Raise so the caller renders its fallback
    # template instead of a blank summary.
    if not content or not content.strip():
        raise GroqError("Groq returned an empty completion.")
    return content
