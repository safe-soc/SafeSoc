"""
SafeSOC — Investigation Service
Turns a natural-language question into one of the supported intents
(SS-044) plus tool parameters, resolving it against the conversation so
far (SS-046): auth failures, IP activity, endpoint snapshot, top alerts,
user activity, cloud events, risky endpoints, attack chain status, and
a tenant-wide overview.

Keyword/pattern classification, not an LLM call: a small, fixed set of
categories that a deterministic classifier can be tested against
without a live LLM (none is available in CI) — the same reasoning that
led the correlation engine (SS-028) to deterministic pattern matching.
The Ollama/Groq clients (SS-042/SS-043) only phrase the final answer.

How a query is handled (resolve_query):
1. Normalize: curly quotes -> ASCII, whitespace collapsed, a lowercase
   copy for matching (the original is kept for display).
2. Deterministic short-circuits that never call a tool or the LLM:
   prompt-injection / cross-tenant phrasing (a fixed refusal — tenant
   scope always comes from the JWT, never from text), action requests
   ("block", "isolate"…), threat-intel lookups with no IP, and noise.
3. Entities: host and user names are matched case-insensitively against
   the tenant's KNOWN entities (get_known_entities, cached) and returned
   in their stored spelling; regexes are only a fallback for names not
   seen yet. Plus IPs, severity, "top N" and time windows.
4. Intent: keyword/rule scores, single-token typo tolerance, and a fixed
   priority order for ties (never "UNKNOWN because of a tie").
5. Follow-ups: an unclassified query inherits the previous turn's intent
   only if it reads like a follow-up ("what about", "now", "which
   users"… or a short query naming an entity/time); its own entities
   then replace the inherited ones. Anything else is UNKNOWN.
6. A missing required parameter (snapshot -> host, user activity ->
   user, IP activity -> ip) becomes a clarifying question; the pending
   intent is remembered so a short reply ("WIN10-FIN-07") completes it.

Context is never saved here. The caller saves it (commit_context) only
after the tool call succeeded, so an errored or out-of-scope turn can't
poison the next one.
"""

import difflib
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.enums import CorrelationPattern, Intent, QueryResolution
from app.db.opensearch import get_alert_entity_terms
from app.db.redis import get_client
from app.models.endpoint import Endpoint
from app.utils.logger import get_logger

logger = get_logger(__name__)


# ── 1. Normalization ───────────────────────────────────────────────

_QUOTE_TRANSLATION = str.maketrans({
    "‘": "'", "’": "'", "‚": "'", "‛": "'", "′": "'",
    "“": '"', "”": '"', "„": '"', "″": '"',
})


@dataclass(frozen=True)
class NormalizedQuery:
    original: str  # as typed, for display
    text: str      # ASCII quotes, single spaces, original case (for case-sensitive fallbacks)
    lower: str     # `text` lowercased, for keyword matching


def normalize_query(query: str) -> NormalizedQuery:
    text = " ".join((query or "").translate(_QUOTE_TRANSLATION).split())
    return NormalizedQuery(original=query or "", text=text, lower=text.lower())


# Host/user-shaped tokens: letters/digits joined by . _ - (so "WIN10-FIN-07?"
# yields "win10-fin-07", "jane.smith's" yields "jane.smith").
_TOKEN_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9._\-]*[a-z0-9])?")


def _tokens(lower: str) -> list[str]:
    return _TOKEN_PATTERN.findall(lower)


# ── Known entities (per tenant, cached) ────────────────────────────

@dataclass(frozen=True)
class KnownEntities:
    """A tenant's known host_ids and usernames, most active first."""
    hosts: tuple[str, ...] = ()
    users: tuple[str, ...] = ()


NO_KNOWN_ENTITIES = KnownEntities()
KNOWN_ENTITIES_KEY_PREFIX = "investigation:known_entities"


def _known_entities_key(tenant_id: str) -> str:
    return f"{KNOWN_ENTITIES_KEY_PREFIX}:{tenant_id}"


def _dedupe(values) -> tuple[str, ...]:
    seen: set[str] = set()
    result = []
    for value in values:
        if value and value.lower() not in seen:
            seen.add(value.lower())
            result.append(value)
    return tuple(result)


async def get_known_entities(db: AsyncSession, tenant_id: uuid.UUID) -> KnownEntities:
    """
    This tenant's known host_ids (endpoints table + distinct host_id in
    recent alerts) and usernames (distinct `user` in recent alerts,
    "unknown" excluded). One OpenSearch aggregation and one small
    Postgres query on a cache miss; cached in Redis per tenant for
    INVESTIGATION_KNOWN_ENTITIES_TTL_SECONDS. Best-effort throughout: a
    failure just means fewer names are recognized (the regex fallbacks
    still apply), never a failed chat turn.
    """
    key = _known_entities_key(str(tenant_id))
    try:
        cached = await get_client().get(key)
        if cached:
            data = json.loads(cached)
            return KnownEntities(hosts=tuple(data.get("hosts", [])), users=tuple(data.get("users", [])))
    except Exception as e:
        logger.warning("Known-entity cache read failed", error_type=type(e).__name__, error=str(e))

    alert_hosts: list[str] = []
    alert_users: list[str] = []
    try:
        terms = await get_alert_entity_terms(
            str(tenant_id),
            lookback_days=settings.INVESTIGATION_KNOWN_ENTITIES_LOOKBACK_DAYS,
            size=settings.INVESTIGATION_KNOWN_ENTITIES_MAX_TERMS,
        )
        alert_hosts, alert_users = terms.get("host_id", []), terms.get("user", [])
    except Exception as e:
        logger.warning("Known-entity alert aggregation failed", error_type=type(e).__name__, error=str(e))

    endpoint_hosts: list[str] = []
    try:
        result = await db.execute(select(Endpoint.host_id).where(Endpoint.tenant_id == tenant_id))
        endpoint_hosts = sorted(result.scalars().all())
    except Exception as e:
        logger.warning("Known-entity endpoint lookup failed", error_type=type(e).__name__, error=str(e))

    known = KnownEntities(hosts=_dedupe([*alert_hosts, *endpoint_hosts]), users=_dedupe(alert_users))
    try:
        await get_client().set(
            key, json.dumps({"hosts": list(known.hosts), "users": list(known.users)}),
            ex=settings.INVESTIGATION_KNOWN_ENTITIES_TTL_SECONDS,
        )
    except Exception as e:
        logger.warning("Known-entity cache write failed", error_type=type(e).__name__, error=str(e))
    return known


def _match_known(tokens: list[str], known: tuple[str, ...]) -> Optional[str]:
    """First token that is a known name (case-insensitive, whole token), in its stored spelling."""
    canonical = {name.lower(): name for name in known}
    for token in tokens:
        if token in canonical:
            return canonical[token]
    return None


# ── 3. Entity extraction ───────────────────────────────────────────

# Fallback for hosts not seen yet: uppercase, hyphenated tokens
# (DESKTOP-042, WEB-SERVER-01). Case-sensitive on purpose — lowercase
# hyphenated words ("brute-force") are not hosts.
_HOST_ID_PATTERN = re.compile(r"\b[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+\b")

# Fallback for users not seen yet: "user X". A captured question/aux
# word ("which user HAS…") is not a name.
_USER_PATTERN = re.compile(r"\buser\s+([A-Za-z][\w.\-]*)", re.IGNORECASE)
_USER_STOPWORDS = frozenset({
    "has", "have", "had", "is", "are", "was", "were",
    "do", "does", "did", "can", "could", "will", "would", "should",
    "been", "being", "activity", "status",
})

_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SEVERITY_PATTERN = re.compile(r"\b(critical|high|medium|low)\b")
_TOP_N_PATTERN = re.compile(r"\btop\s+(\d{1,4})\b")
TOP_N_LIMIT_CAP = 50

_RELATIVE_AMOUNT_PATTERN = re.compile(r"\b(?:last|past)\s+(\d{1,4})\s+(minute|min|hour|hr|day)s?\b")
# Fixed phrases that mean "look back N hours from now".
_RELATIVE_TIME_PHRASES: tuple[tuple[str, int], ...] = (
    ("last hour", 1),
    ("past hour", 1),
    ("last 24 hours", 24),
    ("last week", 24 * 7),
    ("past week", 24 * 7),
)


def _extract_host_id(nq: NormalizedQuery, known: KnownEntities) -> Optional[str]:
    match = _match_known(_tokens(nq.lower), known.hosts)
    if match:
        return match
    fallback = _HOST_ID_PATTERN.search(nq.text)
    return fallback.group(0) if fallback else None


def _extract_user(nq: NormalizedQuery, known: KnownEntities) -> Optional[str]:
    match = _match_known(_tokens(nq.lower), known.users)
    if match:
        return match
    fallback = _USER_PATTERN.search(nq.text)
    if fallback is None:
        return None
    candidate = fallback.group(1)
    return None if candidate.lower() in _USER_STOPWORDS else candidate


def _iso(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


def _extract_time(lower: str, now: datetime) -> dict:
    """
    timerange_hours (what the tools take today) plus, for calendar
    windows, start/end ISO params (UTC days) for the tools to honour in
    a follow-up change. Until they do, timerange_hours always covers the
    whole window — for "yesterday" that's a 48-hour superset — so no
    window is silently cut short.
    """
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)

    amount = _RELATIVE_AMOUNT_PATTERN.search(lower)
    if amount:
        n, unit = int(amount.group(1)), amount.group(2)
        if unit in ("minute", "min"):
            return {"timerange_hours": max(1, -(-n // 60)), "start": _iso(now - timedelta(minutes=n)), "end": _iso(now)}
        if unit == "day":
            return {"timerange_hours": n * 24}
        return {"timerange_hours": n}

    if "yesterday" in lower:
        return {"timerange_hours": 48, "start": _iso(today - timedelta(days=1)), "end": _iso(today)}
    if "this week" in lower:
        monday = today - timedelta(days=today.weekday())
        return {"timerange_hours": 24 * 7, "start": _iso(monday)}
    if "today" in lower:
        return {"timerange_hours": 24, "start": _iso(today)}
    for phrase, hours in _RELATIVE_TIME_PHRASES:
        if phrase in lower:
            return {"timerange_hours": hours}
    return {}


def _extract_entities(query: str, known: KnownEntities = NO_KNOWN_ENTITIES, now: Optional[datetime] = None) -> dict:
    """
    Everything a query names: host_id, user, ip, severity, limit ("top
    N", capped at 50) and time (timerange_hours, plus start/end for
    calendar windows). Only keys actually found are returned, so an
    entity that isn't there is absent rather than guessed. Tools ignore
    keys their input model doesn't declare.
    """
    nq = query if isinstance(query, NormalizedQuery) else normalize_query(query)
    now = now or datetime.now(timezone.utc)
    entities: dict = {}

    host_id = _extract_host_id(nq, known)
    if host_id:
        entities["host_id"] = host_id

    ip_match = _IP_PATTERN.search(nq.text)
    if ip_match:
        entities["ip"] = ip_match.group(0)

    user = _extract_user(nq, known)
    if user:
        entities["user"] = user

    severity = _SEVERITY_PATTERN.search(nq.lower)
    if severity:
        entities["severity"] = severity.group(1)

    top_n = _TOP_N_PATTERN.search(nq.lower)
    if top_n:
        entities["limit"] = max(1, min(int(top_n.group(1)), TOP_N_LIMIT_CAP))

    entities.update(_extract_time(nq.lower, now))
    return entities


# ── 4. Intent classification ───────────────────────────────────────

# Substring phrases, matched against the normalized lowercase query.
# Each matching phrase adds one point to its intent.
_INTENT_KEYWORDS: dict[Intent, tuple[str, ...]] = {
    Intent.AUTH_FAILURES: (
        "failed login", "failed logins", "failed authentication", "login failure", "login failures",
        "authentication failure", "authentication failures", "auth failure", "auth failures",
        "brute force", "brute-force", "bruteforce", "password spray", "trying to log in", "login attempts",
        "login attempt", "unsuccessful login", "unsuccessful authentication", "invalid login", "bad password",
    ),
    Intent.IP_ACTIVITY: (
        "ip address", "from ip", "source ip", "this ip", "that ip", "traffic from",
        "activity from ip", "connections from",
    ),
    Intent.ENDPOINT_SNAPSHOT: (
        "snapshot", "endpoint status", "host status", "endpoint overview", "overview of",
        "everything about", "what's happening on", "whats happening on", "status of", "tell me about",
    ),
    Intent.TOP_ALERTS: (
        "top alerts", "most severe", "highest severity", "high severity", "highest priority", "recent alerts",
        "latest alerts", "worst alerts", "biggest alerts", "most critical alerts", "critical", "look at first",
        "prioritize", "how many alerts", "privilege escalation", "alerts",
    ),
    Intent.USER_ACTIVITY: (
        "user activity", "what did user", "actions by user", "activity for user", "this user",
        "user did", "user has been", "actions taken by", "what has user", "activity for",
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
        "under attack", "compromise in progress", "incidents", "open cases",
    ),
    Intent.OVERVIEW: (
        "summary", "overview", "anything suspicious", "what's going on", "whats going on",
        "what happened today", "status report",
    ),
}

# Phrases with a placeholder, as regexes on the normalized lowercase query.
_INTENT_RULES: dict[Intent, tuple[re.Pattern, ...]] = {
    Intent.ENDPOINT_SNAPSHOT: (re.compile(r"\bis\s+(?:\S+\s+){1,2}compromised\b"),),
    Intent.USER_ACTIVITY: (
        re.compile(r"\bwhat\s+has\s+(?:the\s+)?\S+\s+been\s+doing\b"),
        re.compile(r"\bwhat\s+did\s+\S+\s+do\b"),
    ),
    Intent.RISKY_ENDPOINTS: (
        re.compile(r"\b(?:risky|riskiest|high[- ]risk)\s+(?:machines?|hosts?|servers?|endpoints?|computers?)\b"),
    ),
}

# Ties go to the more specific intent, not to UNKNOWN.
_INTENT_PRIORITY: tuple[Intent, ...] = (
    Intent.AUTH_FAILURES,
    Intent.IP_ACTIVITY,
    Intent.USER_ACTIVITY,
    Intent.ENDPOINT_SNAPSHOT,
    Intent.ATTACK_CHAIN_STATUS,
    Intent.CLOUD_EVENTS,
    Intent.RISKY_ENDPOINTS,
    Intent.TOP_ALERTS,
    Intent.OVERVIEW,
)

# Single-token typo tolerance ("faild logns"): a token that isn't a
# keyword word but is close to one (difflib ratio >= 0.85) is read as it.
_TYPO_MIN_RATIO = 0.85
# 5+ letters on both sides: short words ("what", "user") are too close to
# each other to correct safely.
_TYPO_MIN_LENGTH = 5
_KEYWORD_VOCABULARY = sorted({
    word
    for phrases in _INTENT_KEYWORDS.values()
    for phrase in phrases
    for word in re.findall(r"[a-z]+", phrase)
    if len(word) >= _TYPO_MIN_LENGTH
})

# Minimum accuracy the classifier must hit against
# tests/test_investigation.py's representative query set (SS-044 AC).
INTENT_CLASSIFICATION_ACCURACY_THRESHOLD = 0.80


def _correct_typos(lower: str, known: KnownEntities) -> str:
    known_names = {name.lower() for name in (*known.hosts, *known.users)}

    def fix(match: re.Match) -> str:
        word = match.group(0)
        if len(word) < _TYPO_MIN_LENGTH or word in _KEYWORD_VOCABULARY or word in known_names:
            return word
        close = difflib.get_close_matches(word, _KEYWORD_VOCABULARY, n=1, cutoff=_TYPO_MIN_RATIO)
        return close[0] if close else word

    # Pure-letter words only: anything with digits, dots, hyphens or an
    # apostrophe is a name or a contraction ("what's") and is left alone.
    return re.sub(r"(?<![\w.\-'])[a-z]+(?![\w.\-'])", fix, lower)


def _intent_scores(texts: tuple[str, ...], has_ip: bool) -> dict[Intent, int]:
    """A phrase/rule scores if it matches ANY of `texts` (the query as typed, and typo-corrected)."""
    scores = {
        intent: sum(1 for phrase in phrases if any(phrase in text for text in texts))
        for intent, phrases in _INTENT_KEYWORDS.items()
    }
    for intent, patterns in _INTENT_RULES.items():
        scores[intent] += sum(1 for pattern in patterns if any(pattern.search(text) for text in texts))
    if has_ip:
        scores[Intent.IP_ACTIVITY] += 1
    return scores


def _topic_intent(lower: str, known: KnownEntities, has_ip: bool) -> Optional[Intent]:
    """
    The best-scoring intent from keywords/rules alone (ties by priority),
    or None with no topic at all. Scored on the query as typed AND
    typo-corrected, so a correction can add a match ("faild" -> "failed")
    but never remove one ("compromised" stays matchable).
    """
    scores = _intent_scores((lower, _correct_typos(lower, known)), has_ip)
    best = max(scores.values())
    if best == 0:
        return None
    return next(intent for intent in _INTENT_PRIORITY if scores[intent] == best)


def classify_intent(query: str, known: KnownEntities = NO_KNOWN_ENTITIES) -> Intent:
    """
    The query's intent on its own (no conversation context), or
    Intent.UNKNOWN if it has no topic. A query with no topic keyword
    that names a known host is an endpoint snapshot, one naming a known
    user is user activity. A summary/overview of a named host or user
    is that host's snapshot / that user's activity.
    """
    nq = normalize_query(query)
    entities = _extract_entities(nq, known)
    topic = _topic_intent(nq.lower, known, "ip" in entities)

    if topic == Intent.OVERVIEW:
        if "host_id" in entities:
            return Intent.ENDPOINT_SNAPSHOT
        if "user" in entities:
            return Intent.USER_ACTIVITY
    if topic is not None:
        return topic

    tokens = _tokens(nq.lower)
    if _match_known(tokens, known.hosts):
        return Intent.ENDPOINT_SNAPSHOT
    if _match_known(tokens, known.users):
        return Intent.USER_ACTIVITY
    return Intent.UNKNOWN


# ── 2/5. Deterministic short-circuits ──────────────────────────────

_INJECTION_PATTERN = re.compile(
    r"\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+|your\s+|the\s+|previous\s+|prior\s+|above\s+)*"
    r"(?:instructions?|rules|prompts?|guidelines)\b"
    r"|\bsystem\s+prompt\b"
    r"|\b(?:all|other|every|another|any\s+other)\s+tenants?'?\b"
    r"|\bcross[- ]tenant\b"
)
_ACTION_PATTERN = re.compile(
    r"\b(?:block|isolate|disable|kill(?!\s+chain)|quarantine|reset\s+(?:\S+\s+)?passwords?)\b"
)
_THREAT_INTEL_PATTERN = re.compile(r"\b(?:virustotal|virus\s+total|abuseipdb|reputation)\b")

_CONVERSATIONAL_NOISE = frozenset({
    "hi", "hello", "hey", "hiya", "yo",
    "thanks", "thank you", "thx", "ty",
    "ok", "okay", "k", "sure", "cool", "great", "nice",
    "yes", "no", "yep", "yeah", "nope",
    "bye", "goodbye", "see you", "later",
})


def _is_conversational_noise(query: str) -> bool:
    lower = normalize_query(query).lower
    # Nothing but punctuation / a single character ("?", "h", "...").
    if len(re.sub(r"[\W_]", "", lower)) <= 1:
        return True
    return lower.rstrip("!.?, ") in _CONVERSATIONAL_NOISE


UNKNOWN_INTENT_ANSWER = (
    "I couldn't determine what you're asking. Try asking about failed logins, IP activity, "
    "an endpoint's status, top alerts, user activity, cloud findings, risky endpoints, or "
    "attack chain status."
)
NOISE_ANSWER = (
    "Hi! Ask me about this tenant's security data — failed logins, a host's status, a user's "
    "activity, top alerts, risky endpoints, or active attack chains."
)
ACTION_REQUEST_ANSWER = (
    "I can't take actions from chat. Proposed and approved actions are on the Response/SOAR page."
)
THREAT_INTEL_ANSWER = (
    "I can't query VirusTotal or AbuseIPDB from chat. Threat-intel enrichment results appear in an "
    "incident's Evidence panel. Include an IP address and I'll show SafeSOC's own activity for it."
)
THREAT_INTEL_NOTICE = (
    "I can't query VirusTotal or AbuseIPDB from chat — enrichment results appear in an incident's "
    "Evidence panel. Here is SafeSOC's own activity for this IP:"
)
REFUSAL_ANSWER = (
    "I can't do that. I only answer questions about your own organization's security data, and "
    "I don't change my instructions."
)


def example_questions(known: KnownEntities) -> list[str]:
    host = known.hosts[0] if known.hosts else "WIN10-FIN-07"
    user = known.users[0] if known.users else None
    examples = [f"What's happening on {host}?"]
    if user:
        examples.append(f"What has {user} been doing?")
    examples.append("Show failed logins in the last 24 hours")
    return examples


def _unknown_answer(known: KnownEntities) -> str:
    return f"{UNKNOWN_INTENT_ANSWER} For example: " + "; ".join(f"“{q}”" for q in example_questions(known))


# ── 6. Required parameters ─────────────────────────────────────────

_REQUIRED_PARAM: dict[Intent, str] = {
    Intent.ENDPOINT_SNAPSHOT: "host_id",
    Intent.USER_ACTIVITY: "user",
    Intent.IP_ACTIVITY: "ip",
}


def clarifying_question(missing: str, known: KnownEntities) -> str:
    if missing == "host_id":
        examples = ", ".join(known.hosts[:3]) or "WIN10-FIN-07"
        return f"Which host? For example: {examples}"
    if missing == "user":
        examples = ", ".join(known.users[:3])
        return f"Which user? For example: {examples}" if examples else "Which user?"
    return "Which IP address? For example: 203.0.113.25"


# ── Conversation context (Redis) ───────────────────────────────────
# A namespaced key per (tenant, session), TTL refreshed on every write,
# so an idle conversation's context expires (SS-046 AC).

SESSION_KEY_PREFIX = "investigation:session"

# Maximum (query, answer) pairs kept per session (SS-087).
MAX_TRANSCRIPT_TURNS = 5


def _session_key(tenant_id: str, session_id: str) -> str:
    return f"{SESSION_KEY_PREFIX}:{tenant_id}:{session_id}"


@dataclass(frozen=True)
class ConversationContext:
    intent: Intent
    params: dict
    transcript: list[dict]
    # A clarifying question awaiting its answer: {"intent", "params", "missing"}.
    pending: Optional[dict] = None


async def save_context(
    tenant_id: str, session_id: str, intent: Intent, params: dict,
    transcript: Optional[list[dict]] = None, pending: Optional[dict] = None,
) -> None:
    """Persist the session's context. `transcript` and `pending` default to empty — callers carry them explicitly."""
    client = get_client()
    payload = json.dumps({"intent": intent.value, "params": params, "transcript": transcript or [], "pending": pending})
    await client.set(_session_key(tenant_id, session_id), payload, ex=settings.INVESTIGATION_SESSION_TTL_SECONDS)


async def get_context(tenant_id: str, session_id: str) -> Optional[ConversationContext]:
    """The session's context, or None if no session exists or it has idled out."""
    client = get_client()
    raw = await client.get(_session_key(tenant_id, session_id))
    if raw is None:
        return None
    data = json.loads(raw)
    return ConversationContext(
        intent=Intent(data["intent"]), params=data["params"],
        transcript=data.get("transcript", []), pending=data.get("pending"),
    )


async def commit_context(tenant_id: str, session_id: str, intent: Intent, params: dict) -> None:
    """
    Make a turn's (intent, params) the session's context. Call ONLY after
    the tool call succeeded — a failed or out-of-scope turn must never
    become what the next follow-up inherits. Keeps the transcript; clears
    any pending clarifying question (it has now been answered or
    superseded by a real answer).
    """
    previous = await get_context(tenant_id, session_id)
    transcript = previous.transcript if previous is not None else []
    await save_context(tenant_id, session_id, intent, params, transcript, pending=None)


async def remember_clarification(tenant_id: str, session_id: str, intent: Intent, params: dict, missing: str) -> None:
    """
    Record a clarifying question so the next short reply can complete
    it. Leaves the last successful turn's intent/params untouched; with
    no prior context, the pending intent stands in as the context.
    """
    previous = await get_context(tenant_id, session_id)
    pending = {"intent": intent.value, "params": params, "missing": missing}
    if previous is None:
        await save_context(tenant_id, session_id, intent, {}, [], pending=pending)
    else:
        await save_context(tenant_id, session_id, previous.intent, previous.params, previous.transcript, pending=pending)


async def append_turn(tenant_id: str, session_id: str, query: str, answer: str) -> None:
    """
    Append this turn's (query, answer) pair to the transcript (SS-087),
    capped at MAX_TRANSCRIPT_TURNS (oldest dropped). A no-op if the
    session has idled out.
    """
    context = await get_context(tenant_id, session_id)
    if context is None:
        return
    transcript = [*context.transcript, {"query": query, "answer": answer}][-MAX_TRANSCRIPT_TURNS:]
    await save_context(tenant_id, session_id, context.intent, context.params, transcript, pending=context.pending)


# ── Resolution ─────────────────────────────────────────────────────

_SUCCESS_QUESTION_PATTERN = re.compile(
    r"\bwas\s+(?:it|that|this|the\s+(?:attack|attempt|brute[- ]?force))\s+successful\b"
    r"|\bcompromised\b"
    r"|\bdid\s+(?:they|the\s+attackers?|anyone|someone|it|the\s+attack)\s+(?:get\s+in|break\s+in|succeed)\b"
    r"|\bgot\s+in\b|\bbreached\b"
)
_WINDOW_KEYS = frozenset({"timerange_hours", "start", "end"})
_SUBJECT_KEYS = ("host_id", "user", "ip")
# The tools' default lookback when no time is named.
DEFAULT_LOOKBACK_HOURS = 24

_LATERAL_MOVEMENT_PATTERN = re.compile(r"\blateral(?:ly)?\s+mov(?:e|es|ed|ing|ement)\b")
# Question topics that are really "alerts of this log type".
_LOG_TYPE_TOPICS: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(
        r"\bprivilege[sd]?(?:\s+(?:escalations?|changes?|use))?\b|\bsudo\b|\belevat(?:ion|ed|e)\b"
        r"|\badmin(?:istrator|istrative)?\s+(?:rights|privileges|access)\b"
    ), "privilege"),
    (re.compile(
        r"\b(?:network|outbound|inbound|external)\s+(?:connections?|traffic|activity|events?)\b|\bconnections?\s+to\b"
    ), "network"),
    (re.compile(
        r"\bprocess(?:es)?\s+(?:started|launched|ran|run|executed|events?|activity)\b|\bprocesses\b"
        r"|\bcommands?\s+(?:executed|run|ran)\b|\b(?:executed|ran)\s+commands?\b"
    ), "process"),
    (re.compile(
        r"\bfiles?\s+(?:changes?|changed|modifications?|modified|events?|activity|access)\b|\b(?:modified|changed)\s+files?\b"
    ), "file"),
)

# Whole-word markers that make a topic-less query a follow-up.
_FOLLOW_UP_MARKERS = (
    "what about", "how about", "and", "now", "also", "same for", "which users", "which hosts",
    "was it", "was the attack", "were they", "those", "that host", "them",
)
_FOLLOW_UP_PATTERN = re.compile(r"\b(?:" + "|".join(re.escape(marker) for marker in _FOLLOW_UP_MARKERS) + r")\b")
_SHORT_FOLLOW_UP_MAX_WORDS = 6


def _looks_like_follow_up(nq: NormalizedQuery, entities: dict) -> bool:
    if _FOLLOW_UP_PATTERN.search(nq.lower):
        return True
    return len(nq.lower.split()) <= _SHORT_FOLLOW_UP_MAX_WORDS and bool(entities)


@dataclass(frozen=True)
class Resolution:
    """What to do with a query. Only kind == TOOL calls a tool; every other kind carries its answer in `message`."""
    kind: QueryResolution
    intent: Intent
    params: dict = field(default_factory=dict)
    message: Optional[str] = None
    # Prefixed to the tool-based answer (e.g. the threat-intel explanation).
    notice: Optional[str] = None
    # For CLARIFY: which required parameter is missing.
    missing: Optional[str] = None


def _finalize(intent: Intent, params: dict, known: KnownEntities, notice: Optional[str] = None) -> Resolution:
    missing = _REQUIRED_PARAM.get(intent)
    if missing and not params.get(missing):
        return Resolution(
            kind=QueryResolution.CLARIFY, intent=intent, params=params,
            message=clarifying_question(missing, known), missing=missing,
        )
    return Resolution(kind=QueryResolution.TOOL, intent=intent, params=params, notice=notice)


async def resolve_query(
    tenant_id: str, session_id: str, query: str,
    known: KnownEntities = NO_KNOWN_ENTITIES, now: Optional[datetime] = None,
) -> Resolution:
    """
    Decide how to handle `query` in this session (see the module
    docstring for the full order). Reads the saved context but never
    writes it: the caller commits context only after a successful tool
    call (commit_context) and records a clarifying question with
    remember_clarification.
    """
    nq = normalize_query(query)

    if _INJECTION_PATTERN.search(nq.lower):
        return Resolution(kind=QueryResolution.REFUSAL, intent=Intent.UNKNOWN, message=REFUSAL_ANSWER)
    if _ACTION_PATTERN.search(nq.lower):
        return Resolution(kind=QueryResolution.ACTION_REQUEST, intent=Intent.UNKNOWN, message=ACTION_REQUEST_ANSWER)
    if _is_conversational_noise(query):
        return Resolution(kind=QueryResolution.NOISE, intent=Intent.UNKNOWN, message=NOISE_ANSWER)

    entities = _extract_entities(nq, known, now)

    if _THREAT_INTEL_PATTERN.search(nq.lower):
        if "ip" not in entities:
            return Resolution(kind=QueryResolution.THREAT_INTEL, intent=Intent.UNKNOWN, message=THREAT_INTEL_ANSWER)
        return _finalize(Intent.IP_ACTIVITY, entities, known, notice=THREAT_INTEL_NOTICE)

    previous = await get_context(tenant_id, session_id)
    topic = _topic_intent(nq.lower, known, "ip" in entities)

    # A short reply that supplies what the last clarifying question asked for.
    pending = previous.pending if previous is not None else None
    if pending and topic is None and entities.get(pending["missing"]):
        return _finalize(Intent(pending["intent"]), {**pending["params"], **entities}, known)

    # "Was it successful?" / "is X compromised?" / "did they get in?" is
    # answered by a host's full snapshot (every alert type, plus logins
    # that succeeded after failures) — never by re-running whatever
    # narrower search came before, which can't see a success. With no
    # host in the query or the conversation, the tenant-wide overview.
    # It never inherits a time window (an earlier "yesterday" would hide a
    # success that happened today) and looks back at least the default
    # 24 hours, unless it bounds the window itself.
    if _SUCCESS_QUESTION_PATTERN.search(nq.lower):
        inherited = previous.params if previous is not None else {}
        params = dict(entities)
        if not params.get("start"):
            params["timerange_hours"] = max(params.get("timerange_hours", DEFAULT_LOOKBACK_HOURS), DEFAULT_LOOKBACK_HOURS)
        host_id = entities.get("host_id") or inherited.get("host_id")
        if host_id:
            return _finalize(Intent.ENDPOINT_SNAPSHOT, {**params, "host_id": host_id}, known)
        return _finalize(Intent.OVERVIEW, params, known)

    # Activity-type topics: "lateral movement" is a detected chain
    # pattern; privilege / network / process / file questions are alerts
    # of that log type — never every alert.
    if _LATERAL_MOVEMENT_PATTERN.search(nq.lower):
        return _finalize(Intent.ATTACK_CHAIN_STATUS, {"category": CorrelationPattern.LATERAL_MOVEMENT.value}, known)
    log_type = next((log_type for pattern, log_type in _LOG_TYPE_TOPICS if pattern.search(nq.lower)), None)
    if log_type and topic in (None, Intent.TOP_ALERTS, Intent.OVERVIEW):
        return _finalize(Intent.TOP_ALERTS, {**entities, "log_type": log_type}, known)

    if topic is not None:
        intent = classify_intent(nq.text, known)
        return _finalize(intent, entities, known)

    # No topic of its own: a follow-up inherits the previous turn, with
    # every entity it names replacing the inherited one of that kind. An
    # inherited time window only carries over while the follow-up stays
    # on the same subject: naming a new host/user/IP without a time of
    # its own resets to the default lookback.
    if previous is not None and _looks_like_follow_up(nq, entities):
        inherited = dict(previous.params)
        names_new_subject = any(
            entities.get(key) and entities[key] != inherited.get(key) for key in _SUBJECT_KEYS
        )
        # A time the follow-up states replaces the inherited window
        # wholesale (never "last 6 hours" next to an old start/end).
        if _WINDOW_KEYS & entities.keys() or names_new_subject:
            for key in _WINDOW_KEYS:
                inherited.pop(key, None)
        return _finalize(previous.intent, {**inherited, **entities}, known)

    # Not a follow-up: a named host/user on its own is still a question.
    intent = classify_intent(nq.text, known)
    if intent != Intent.UNKNOWN:
        return _finalize(intent, entities, known)
    return Resolution(kind=QueryResolution.UNKNOWN, intent=Intent.UNKNOWN, message=_unknown_answer(known))
