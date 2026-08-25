"""
SafeSOC — Investigation Service
Classifies a natural-language query into one of the 8 SRS-defined
intents (SS-044): auth failures, IP activity, endpoint snapshot, top
alerts, user activity, cloud events, risky endpoints, attack chain
status.

Keyword/pattern classification, not an LLM call: this is a small,
fixed, closed set of categories, and a deterministic classifier is
directly testable against a documented accuracy threshold without a
live LLM dependency (no Ollama/Groq server is available in CI) — the
same reasoning that already led the correlation engine (SS-028) to use
deterministic pattern matching rather than a model for a similarly
fixed set of attack chain patterns. The Ollama/Groq clients (SS-042/
SS-043) are used downstream, for generating the assistant's actual
natural-language *answer* once a tool's data comes back (SS-046/SS-047),
not for classification.
"""

import json
import re
from dataclasses import dataclass
from typing import Optional

from app.core.config import settings
from app.core.enums import Intent
from app.db.redis import get_client

# Each phrase is matched as a case-insensitive substring of the query.
# Order doesn't matter — every intent's phrases are checked and scored;
# the highest-scoring intent wins (see classify_intent).
_INTENT_KEYWORDS: dict[Intent, tuple[str, ...]] = {
    Intent.AUTH_FAILURES: (
        "failed login", "failed logins", "failed authentication", "login failure", "login failures",
        "authentication failure", "authentication failures", "auth failure", "auth failures",
        "brute force", "unsuccessful login", "unsuccessful authentication", "invalid login",
        "bad password", "login attempt",
    ),
    Intent.IP_ACTIVITY: (
        "ip address", "from ip", "source ip", "this ip", "that ip", "traffic from",
        "activity from ip", "connections from",
    ),
    Intent.ENDPOINT_SNAPSHOT: (
        "snapshot", "endpoint status", "host status", "endpoint overview", "overview of",
        "everything about", "what's happening on", "whats happening on", "give me a summary of",
        "status of host", "status of endpoint",
    ),
    Intent.TOP_ALERTS: (
        "top alerts", "most severe", "highest severity", "highest priority", "recent alerts",
        "latest alerts", "worst alerts", "biggest alerts", "most critical alerts",
    ),
    Intent.USER_ACTIVITY: (
        "user activity", "what did user", "actions by user", "activity for user", "this user",
        "user did", "user has been", "actions taken by", "what has user",
    ),
    Intent.CLOUD_EVENTS: (
        "cloud finding", "cloud findings", "cloud event", "cloud events", "aws", "cloudlens",
        "iam ", "s3 bucket", "iam misconfiguration", "cloud posture", "cloud security",
    ),
    Intent.RISKY_ENDPOINTS: (
        "riskiest", "risky endpoint", "risky endpoints", "risky host", "high risk endpoint",
        "highest risk", "most risky", "risk score", "endpoints by risk",
    ),
    Intent.ATTACK_CHAIN_STATUS: (
        "attack chain", "attack chains", "correlation status", "incident status", "active incident",
        "ongoing incident", "chain detected", "open incidents", "in progress attack",
        "under attack", "compromise in progress",
    ),
}

# A literal IP address is a strong, mostly-unambiguous signal for
# IP_ACTIVITY even when the query doesn't use one of the phrases above
# (e.g. "what has 45.33.32.156 been doing?").
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Minimum accuracy the classifier must hit against
# tests/test_investigation.py's representative query set before this
# issue's AC is considered satisfied. Documented here, not just in the
# test, so the threshold is visible next to the classifier it gates.
INTENT_CLASSIFICATION_ACCURACY_THRESHOLD = 0.80


def classify_intent(query: str) -> Intent:
    """
    Classify a natural-language query into one of the 8 supported
    intents, or Intent.UNKNOWN if no intent matches confidently.

    Scores each intent by how many of its keyword phrases appear in the
    (lowercased) query, plus an IP-address-literal boost for
    IP_ACTIVITY. The highest-scoring intent wins; a zero score or a tie
    for the highest score is treated as unclassifiable (SS-044 AC:
    "unclassifiable queries have a defined fallback behavior") rather
    than guessed.
    """
    normalized = query.lower()

    scores: dict[Intent, int] = {intent: 0 for intent in _INTENT_KEYWORDS}
    for intent, phrases in _INTENT_KEYWORDS.items():
        scores[intent] = sum(1 for phrase in phrases if phrase in normalized)

    if _IP_PATTERN.search(query):
        scores[Intent.IP_ACTIVITY] += 1

    best_score = max(scores.values())
    if best_score == 0:
        return Intent.UNKNOWN

    top_intents = [intent for intent, score in scores.items() if score == best_score]
    if len(top_intents) > 1:
        return Intent.UNKNOWN

    return top_intents[0]


# ── SS-046: conversation context/session state ────────────────────
# Redis-backed, mirroring services/correlation.py's sliding-window
# pattern (SS-027): a namespaced key per (tenant, session), TTL
# refreshed on every write so an idle conversation's context
# eventually expires (SRS §3.3 / SS-046 AC) rather than living forever.

SESSION_KEY_PREFIX = "investigation:session"


def _session_key(tenant_id: str, session_id: str) -> str:
    return f"{SESSION_KEY_PREFIX}:{tenant_id}:{session_id}"


@dataclass(frozen=True)
class ConversationContext:
    intent: Intent
    params: dict


async def save_context(tenant_id: str, session_id: str, intent: Intent, params: dict) -> None:
    """
    Persist a turn's resolved intent + tool parameters as this
    session's context, for a follow-up turn to build on. Refreshes the
    idle-expiry TTL on every write, same as CORRELATION_WINDOW_TTL.
    """
    client = get_client()
    payload = json.dumps({"intent": intent.value, "params": params})
    await client.set(_session_key(tenant_id, session_id), payload, ex=settings.INVESTIGATION_SESSION_TTL_SECONDS)


async def get_context(tenant_id: str, session_id: str) -> Optional[ConversationContext]:
    """The previous turn's context, or None if no session exists or it has idled out."""
    client = get_client()
    raw = await client.get(_session_key(tenant_id, session_id))
    if raw is None:
        return None
    data = json.loads(raw)
    return ConversationContext(intent=Intent(data["intent"]), params=data["params"])


# Endpoint hostnames in this codebase are consistently formatted as
# uppercase, hyphenated tokens (DESKTOP-042, WEB-SERVER-01, ...) — see
# every adapter/test fixture that names a host_id. Used to pick "host
# X" out of a query so it can be carried into a follow-up turn.
_HOST_ID_PATTERN = re.compile(r"\b[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+\b")


def _extract_host_id(query: str) -> Optional[str]:
    match = _HOST_ID_PATTERN.search(query)
    return match.group(0) if match else None


# Conversational noise (greetings, acknowledgements, sign-offs) is
# *also* unclassifiable by _INTENT_KEYWORDS — indistinguishable, by
# keyword score alone, from a genuine topic-less follow-up like "what
# about yesterday?" (SS-046's own worked example). Without this list,
# resolve_query() below treated both cases identically and silently
# re-answered a bare "Hello" with whatever the previous turn's topic
# was (reported live, reproduced in tests/test_investigation.py).
# Matched as a whole-string comparison (after trimming and dropping
# trailing punctuation), not a substring — so it only catches a
# message that *is* one of these, not one that merely contains "hi".
_CONVERSATIONAL_NOISE = frozenset({
    "hi", "hello", "hey", "hiya", "yo",
    "thanks", "thank you", "thx", "ty",
    "ok", "okay", "k", "sure", "cool", "great", "nice",
    "yes", "no", "yep", "yeah", "nope",
    "bye", "goodbye", "see you", "later",
})


def _is_conversational_noise(query: str) -> bool:
    normalized = query.strip().lower().rstrip("!.?,")
    return normalized in _CONVERSATIONAL_NOISE


async def resolve_query(tenant_id: str, session_id: str, query: str) -> tuple[Intent, dict]:
    """
    Classify `query` and resolve it against this session's prior
    context, so a follow-up that doesn't restate its subject (SS-046
    AC's own example: "show failed logins for host X" -> "what about
    yesterday?") still resolves to the right intent and parameters
    instead of falling back to Intent.UNKNOWN.

    A query that classifies to a specific intent on its own is treated
    as a fresh turn: its params start empty, plus a host_id if the
    query names one (the AC's own worked example turns on exactly
    this — "host X" must actually be captured for a later "what about
    yesterday?" to have something to inherit). A query that *doesn't*
    classify on its own, with context available from a still-live
    session, inherits the previous turn's intent and parameters
    wholesale instead — *unless* it's recognizable conversational
    noise (a bare greeting/thanks/etc.), which is answered as
    Intent.UNKNOWN without disturbing the saved context, so a later
    real follow-up can still resolve against the actual prior topic.
    Resolving other new entities in a follow-up (e.g. turning
    "yesterday" into an actual date range) is intentionally out of
    scope — SS-044 classifies intent, not entities, and this issue is
    about carrying context forward, not general natural-language
    date/entity extraction.

    The resolved (intent, params) becomes the new saved context (noise
    turns excepted, per above), so a chain of follow-ups keeps building
    on the same subject.
    """
    intent = classify_intent(query)
    previous = await get_context(tenant_id, session_id)

    if intent == Intent.UNKNOWN and previous is not None and not _is_conversational_noise(query):
        intent = previous.intent
        params = dict(previous.params)
    elif intent == Intent.UNKNOWN:
        return intent, {}
    else:
        params = {}
        host_id = _extract_host_id(query)
        if host_id:
            params["host_id"] = host_id

    await save_context(tenant_id, session_id, intent, params)
    return intent, params
