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


def generate(prompt: str, max_output_tokens: Optional[int] = None) -> str:
    """
    Send a prompt to Groq's chat completions API and return the
    completion text.

    max_output_tokens defaults to settings.INVESTIGATION_LLM_MAX_OUTPUT_TOKENS
    when omitted — see clients/ollama.py's generate() for why callers
    with a different latency budget pass their own value instead.

    Raises:
        GroqError: if Groq is unreachable, times out, or returns an error response.
    """
    if max_output_tokens is None:
        max_output_tokens = settings.INVESTIGATION_LLM_MAX_OUTPUT_TOKENS
    try:
        response = requests.post(
            f"{GROQ_BASE_URL}/chat/completions",
            headers={"Authorization": f"Bearer {settings.GROQ_API_KEY}"},
            json={
                "model": settings.GROQ_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                # Same bound as ollama.py's num_predict, for interface/behavior
                # parity between providers (latency diagnosis).
                "max_tokens": max_output_tokens,
            },
            timeout=60,
        )
        response.raise_for_status()
    except requests.RequestException as e:
        raise GroqError(f"Groq request failed: {e}") from e

    try:
        return response.json()["choices"][0]["message"]["content"]
    except (KeyError, IndexError) as e:
        raise GroqError(f"Groq returned an unexpected response shape: {e}") from e
