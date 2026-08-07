"""
SafeSOC — Ollama Client
HTTP client against a local Ollama instance (settings.ollama_url),
running settings.OLLAMA_MODEL, for the natural-language investigation
assistant (SS-042).
"""

import requests

from app.core.config import settings


class OllamaError(Exception):
    """Raised when the local Ollama instance is unreachable or returns an error."""


def generate(prompt: str) -> str:
    """
    Send a prompt to the local Ollama instance and return its completion.

    Raises:
        OllamaError: if Ollama is unreachable, times out, or returns an error response.
    """
    try:
        response = requests.post(
            f"{settings.ollama_url}/api/generate",
            json={"model": settings.OLLAMA_MODEL, "prompt": prompt, "stream": False},
            timeout=60,
        )
        response.raise_for_status()
    except requests.RequestException as e:
        raise OllamaError(f"Ollama request failed: {e}") from e

    return response.json().get("response", "")
