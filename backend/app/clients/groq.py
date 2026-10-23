"""
SafeSOC — Groq Client
Cloud-based LLM completion via Groq's OpenAI-compatible chat
completions API, the fallback path when settings.LLM_PROVIDER == "groq"
(SS-043). Same interface contract as clients/ollama.py (SS-042):
generate(prompt, max_output_tokens=None) -> str, so callers can select
a provider without caring which one is active.
"""

import re
import time
from typing import Optional

import requests

from app.core.config import settings

GROQ_BASE_URL = "https://api.groq.com/openai/v1"


class GroqError(Exception):
    """Raised when Groq is unreachable or returns an error."""


class GroqRateLimitError(GroqError):
    """Groq answered 429 and the wait it asked for doesn't fit the caller's time budget."""

    def __init__(self, message: str, retry_after_seconds: Optional[float] = None):
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


# Leave this much of the budget for the retried request itself.
_RETRY_REQUEST_MARGIN_SECONDS = 1.5
_DURATION_PART = re.compile(r"(\d+(?:\.\d+)?)(ms|h|m|s)")


def _parse_duration(value: Optional[str]) -> Optional[float]:
    """Seconds from a Retry-After value ("2", "0.5") or a Groq reset header ("1m30.5s", "7.66s", "250ms")."""
    if not value:
        return None
    value = value.strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    parts = _DURATION_PART.findall(value)
    if not parts:
        return None
    scale = {"h": 3600.0, "m": 60.0, "s": 1.0, "ms": 0.001}
    return sum(float(number) * scale[unit] for number, unit in parts)


def retry_after_seconds(response: requests.Response) -> Optional[float]:
    """
    How long Groq asked us to wait: Retry-After when present, otherwise
    the longer of the x-ratelimit-reset-requests/-tokens headers (we
    can't tell which limit was hit, so wait for both). None if absent.
    """
    retry_after = _parse_duration(response.headers.get("retry-after"))
    if retry_after is not None:
        return retry_after
    resets = [
        _parse_duration(response.headers.get(header))
        for header in ("x-ratelimit-reset-requests", "x-ratelimit-reset-tokens")
    ]
    resets = [reset for reset in resets if reset is not None]
    return max(resets) if resets else None


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


def _post(prompt: str, max_output_tokens: int) -> requests.Response:
    try:
        return requests.post(
            f"{GROQ_BASE_URL}/chat/completions",
            headers={"Authorization": f"Bearer {settings.GROQ_API_KEY}"},
            json=build_payload(prompt, max_output_tokens),
            timeout=60,
        )
    except requests.RequestException as e:
        raise GroqError(f"Groq request failed: {e}") from e


def generate(prompt: str, max_output_tokens: Optional[int] = None, time_budget_seconds: Optional[float] = None) -> str:
    """
    Send a prompt to Groq's chat completions API and return the
    completion text.

    max_output_tokens defaults to settings.INVESTIGATION_LLM_MAX_OUTPUT_TOKENS
    when omitted — see clients/ollama.py's generate() for why callers
    with a different latency budget pass their own value instead.

    Rate limiting (429): retried ONCE, only if the wait Groq asks for
    (retry_after_seconds) plus a margin for the retried request fits in
    what's left of `time_budget_seconds` (the caller's whole budget for
    this call). Otherwise, or if the retry is also limited, raises
    GroqRateLimitError so the caller can say "AI busy" rather than
    "error". With no budget given, a 429 is never retried.

    Raises:
        GroqRateLimitError: rate limited and no retry fit the budget.
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
    started = time.monotonic()
    response = _post(prompt, max_output_tokens)
    if response.status_code == 429:
        wait = retry_after_seconds(response)
        remaining = (time_budget_seconds or 0.0) - (time.monotonic() - started)
        if wait is None or wait + _RETRY_REQUEST_MARGIN_SECONDS > remaining:
            raise GroqRateLimitError(f"Groq rate limited the request (retry after {wait}s).", wait)
        time.sleep(wait)
        response = _post(prompt, max_output_tokens)
        if response.status_code == 429:
            raise GroqRateLimitError("Groq rate limited the request again after one retry.", retry_after_seconds(response))
    try:
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
