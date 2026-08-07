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

import re

from app.core.enums import Intent

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
