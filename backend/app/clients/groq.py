"""
SafeSOC — Groq Client
Cloud-based LLM completion via Groq's OpenAI-compatible chat
completions API, the fallback path when settings.LLM_PROVIDER == "groq"
(SS-043). Same interface contract as clients/ollama.py (SS-042):
generate(prompt) -> str, so callers can select a provider without
caring which one is active.
"""

import requests

from app.core.config import settings

GROQ_BASE_URL = "https://api.groq.com/openai/v1"


class GroqError(Exception):
    """Raised when Groq is unreachable or returns an error."""


def generate(prompt: str) -> str:
    """
    Send a prompt to Groq's chat completions API and return the
    completion text.

    Raises:
        GroqError: if Groq is unreachable, times out, or returns an error response.
    """
    try:
        response = requests.post(
            f"{GROQ_BASE_URL}/chat/completions",
            headers={"Authorization": f"Bearer {settings.GROQ_API_KEY}"},
            json={
                "model": settings.GROQ_MODEL,
                "messages": [{"role": "user", "content": prompt}],
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
