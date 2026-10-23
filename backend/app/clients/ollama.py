"""
SafeSOC — Ollama Client
HTTP client against a local Ollama instance (settings.ollama_url),
running settings.OLLAMA_MODEL, for the natural-language investigation
assistant (SS-042).
"""

from typing import Optional

import requests

from app.core.config import settings


class OllamaError(Exception):
    """Raised when the local Ollama instance is unreachable or returns an error."""


def generate(prompt: str, max_output_tokens: Optional[int] = None, time_budget_seconds: Optional[float] = None) -> str:
    """
    Send a prompt to the local Ollama instance and return its completion.

    max_output_tokens defaults to settings.INVESTIGATION_LLM_MAX_OUTPUT_TOKENS
    (the interactive-chat budget) when omitted, but callers with a
    different latency budget — e.g. services/incident_narrative.py,
    whose own timeout is more generous — pass their own value instead
    of sharing the chat's tighter one.

    time_budget_seconds (same contract as clients/groq.py) bounds the
    HTTP request itself, so a hung Ollama doesn't keep a worker thread
    busy long after the caller gave up. Ollama has no rate limiting.

    Raises:
        OllamaError: if Ollama is unreachable, times out, or returns an error response.
    """
    if max_output_tokens is None:
        max_output_tokens = settings.INVESTIGATION_LLM_MAX_OUTPUT_TOKENS
    try:
        response = requests.post(
            f"{settings.ollama_url}/api/generate",
            json={
                "model": settings.OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
                # Bounds generation time (latency diagnosis, SS-090-adjacent) —
                # unbounded, a real prompt measured 358-364 output tokens.
                "options": {"num_predict": max_output_tokens},
            },
            timeout=min(60, time_budget_seconds) if time_budget_seconds else 60,
        )
        response.raise_for_status()
    except requests.RequestException as e:
        raise OllamaError(f"Ollama request failed: {e}") from e

    return response.json().get("response", "")
