"""
SafeSOC — Investigation Service Tests
"""

from datetime import datetime, timezone

import pytest

from app.core.config import settings
from app.core.enums import Intent, QueryResolution
from app.services import investigation
from app.services.investigation import (
    INTENT_CLASSIFICATION_ACCURACY_THRESHOLD,
    MAX_TRANSCRIPT_TURNS,
    append_turn,
    classify_intent,
    commit_context,
    get_context,
    resolve_query,
    save_context,
)

# Representative queries per intent, phrased the way a SOC analyst would
# actually type them (not hand-picked to trivially match the keyword
# lists) — this is what test_intent_classification_meets_the_accuracy_threshold
# measures against SS-044's documented threshold.
_LABELED_QUERIES: list[tuple[str, Intent]] = [
    # Intent.AUTH_FAILURES
    ("Show me failed logins for host DESKTOP-042", Intent.AUTH_FAILURES),
    ("What authentication failures happened today?", Intent.AUTH_FAILURES),
    ("List brute force attempts against our servers", Intent.AUTH_FAILURES),
    ("Any unsuccessful login attempts recently?", Intent.AUTH_FAILURES),
    ("Show failed authentication events from the last hour", Intent.AUTH_FAILURES),
    ("Who had invalid login attempts this week?", Intent.AUTH_FAILURES),
    ("Give me all auth failures for user admin", Intent.AUTH_FAILURES),
    ("Show me bad password attempts on the finance server", Intent.AUTH_FAILURES),
    ("Failed login attempts via SSH in the last hour", Intent.AUTH_FAILURES),
    ("Were there any login failures on the web server?", Intent.AUTH_FAILURES),
    # Intent.IP_ACTIVITY
    ("What activity came from IP 45.33.32.156?", Intent.IP_ACTIVITY),
    ("Show me everything from source IP 10.0.0.5", Intent.IP_ACTIVITY),
    ("What has 203.0.113.9 been doing on our network?", Intent.IP_ACTIVITY),
    ("List all connections from this IP address", Intent.IP_ACTIVITY),
    ("Show traffic from 198.51.100.1", Intent.IP_ACTIVITY),
    ("What did 192.168.1.42 do in the last 24 hours?", Intent.IP_ACTIVITY),
    ("Give me activity from ip 172.16.0.9", Intent.IP_ACTIVITY),
    ("Any suspicious behavior from that IP?", Intent.IP_ACTIVITY),
    # Intent.ENDPOINT_SNAPSHOT
    ("Give me a snapshot of DESKTOP-042", Intent.ENDPOINT_SNAPSHOT),
    ("What's the status of host WEB-SERVER-01?", Intent.ENDPOINT_SNAPSHOT),
    ("Show me an overview of the finance laptop", Intent.ENDPOINT_SNAPSHOT),
    ("Give me a summary of DESKTOP-042", Intent.ENDPOINT_SNAPSHOT),
    ("What's happening on WEB-SERVER-01 right now?", Intent.ENDPOINT_SNAPSHOT),
    ("Tell me everything about host DB-PROD-03", Intent.ENDPOINT_SNAPSHOT),
    ("What is the endpoint status for DESKTOP-042?", Intent.ENDPOINT_SNAPSHOT),
    ("Endpoint overview for the accounting server", Intent.ENDPOINT_SNAPSHOT),
    # Intent.TOP_ALERTS
    ("Show me the top alerts from today", Intent.TOP_ALERTS),
    ("What are the most severe alerts this week?", Intent.TOP_ALERTS),
    ("List the highest severity alerts", Intent.TOP_ALERTS),
    ("What are the highest priority alerts right now?", Intent.TOP_ALERTS),
    ("Give me the recent alerts across all hosts", Intent.TOP_ALERTS),
    ("Show the latest alerts in the last hour", Intent.TOP_ALERTS),
    ("What are the worst alerts today?", Intent.TOP_ALERTS),
    ("Show me the most critical alerts", Intent.TOP_ALERTS),
    # Intent.USER_ACTIVITY
    ("What did user john.doe do today?", Intent.USER_ACTIVITY),
    ("Show activity for user admin", Intent.USER_ACTIVITY),
    ("What actions by user bob were logged?", Intent.USER_ACTIVITY),
    ("List all actions taken by the service account", Intent.USER_ACTIVITY),
    ("What has user alice been doing this week?", Intent.USER_ACTIVITY),
    ("Give me the activity for user contractor1", Intent.USER_ACTIVITY),
    ("What did this user do on DESKTOP-042?", Intent.USER_ACTIVITY),
    # Intent.CLOUD_EVENTS
    ("Show me the cloud findings from the last scan", Intent.CLOUD_EVENTS),
    ("What AWS issues do we currently have?", Intent.CLOUD_EVENTS),
    ("List CloudLens findings for this account", Intent.CLOUD_EVENTS),
    ("Any IAM misconfigurations detected?", Intent.CLOUD_EVENTS),
    ("Show me S3 bucket exposure issues", Intent.CLOUD_EVENTS),
    ("What's our current cloud security posture?", Intent.CLOUD_EVENTS),
    ("List recent cloud events", Intent.CLOUD_EVENTS),
    # Intent.RISKY_ENDPOINTS
    ("Which endpoints are riskiest right now?", Intent.RISKY_ENDPOINTS),
    ("Show me high risk endpoints", Intent.RISKY_ENDPOINTS),
    ("What's our riskiest host?", Intent.RISKY_ENDPOINTS),
    ("List endpoints by risk score", Intent.RISKY_ENDPOINTS),
    ("Which hosts have the highest risk right now?", Intent.RISKY_ENDPOINTS),
    ("Show me the most risky endpoints in the network", Intent.RISKY_ENDPOINTS),
    ("Are there any risky endpoints I should look at?", Intent.RISKY_ENDPOINTS),
    # Intent.ATTACK_CHAIN_STATUS
    ("Is there an active attack chain right now?", Intent.ATTACK_CHAIN_STATUS),
    ("Show me the correlation status for today", Intent.ATTACK_CHAIN_STATUS),
    ("Any ongoing incidents I should know about?", Intent.ATTACK_CHAIN_STATUS),
    ("Was an attack chain detected recently?", Intent.ATTACK_CHAIN_STATUS),
    ("What open incidents do we have?", Intent.ATTACK_CHAIN_STATUS),
    ("Is a compromise in progress on any host?", Intent.ATTACK_CHAIN_STATUS),
    ("Are we currently under attack?", Intent.ATTACK_CHAIN_STATUS),
    # Intent.OVERVIEW
    ("Anything suspicious today?", Intent.OVERVIEW),
    ("Give me a summary of the last hour", Intent.OVERVIEW),
    ("What's going on in our environment?", Intent.OVERVIEW),
    ("I need a status report for the morning standup", Intent.OVERVIEW),
    # Harder cases: novel phrasing that doesn't hit the classifier's
    # keyword lists directly. Included deliberately so the accuracy
    # threshold is measured honestly rather than trivially satisfied —
    # a rule-based classifier is expected to miss some of these.
    ("Has anyone tried to brute-force their way into DESKTOP-042?", Intent.AUTH_FAILURES),
    ("I keep seeing rejected sign-in attempts, what is going on?", Intent.AUTH_FAILURES),
    ("Give me the full picture on WEB-SERVER-01", Intent.ENDPOINT_SNAPSHOT),
    ("What are we most worried about right now?", Intent.TOP_ALERTS),
    ("What has contractor42 been up to lately?", Intent.USER_ACTIVITY),
    ("Anything weird happening in our AWS account?", Intent.CLOUD_EVENTS),
    ("Which machine should I patch first because of risk?", Intent.RISKY_ENDPOINTS),
    ("Do we have a multi-stage attack unfolding?", Intent.ATTACK_CHAIN_STATUS),
    ("Can you recommend a good pizza place?", Intent.UNKNOWN),
    ("What's on TV tonight?", Intent.UNKNOWN),
]


def test_intent_classification_meets_the_accuracy_threshold():
    """
    SS-044 AC: a test set of representative queries per intent
    classifies correctly at a documented accuracy threshold
    (INTENT_CLASSIFICATION_ACCURACY_THRESHOLD, 80%).
    """
    correct = sum(1 for query, expected in _LABELED_QUERIES if classify_intent(query) == expected)
    accuracy = correct / len(_LABELED_QUERIES)

    assert accuracy >= INTENT_CLASSIFICATION_ACCURACY_THRESHOLD, (
        f"Intent classification accuracy {accuracy:.0%} is below the documented "
        f"{INTENT_CLASSIFICATION_ACCURACY_THRESHOLD:.0%} threshold"
    )


def test_every_intent_has_at_least_one_representative_query():
    """Sanity check on the test set itself, not the classifier."""
    covered = {expected for _, expected in _LABELED_QUERIES}
    assert (set(Intent) - {Intent.UNKNOWN}).issubset(covered)


# ── Fallback behavior (SS-044 AC: unclassifiable queries have a defined fallback) ──

def test_an_unrelated_query_falls_back_to_unknown():
    assert classify_intent("What's the weather like today?") == Intent.UNKNOWN


def test_an_empty_query_falls_back_to_unknown():
    assert classify_intent("") == Intent.UNKNOWN


def test_a_query_matching_no_keywords_falls_back_to_unknown():
    assert classify_intent("asdkjhaskjdh qwoiuqwoiu") == Intent.UNKNOWN


def test_classification_is_case_insensitive():
    assert classify_intent("SHOW ME FAILED LOGINS") == Intent.AUTH_FAILURES
    assert classify_intent("show me failed logins") == Intent.AUTH_FAILURES


# ── SS-046: conversation context/session state ────────────────────

class _FakeRedisClient:
    """Minimal in-memory string-KV fake with TTL tracking, mirroring tests/test_correlation.py's sorted-set fake."""

    def __init__(self):
        self._store: dict[str, str] = {}
        self.set_calls: list[tuple[str, int]] = []  # (key, ex) for every set()

    async def set(self, key, value, ex=None):
        self._store[key] = value
        self.set_calls.append((key, ex))

    async def get(self, key):
        return self._store.get(key)


@pytest.fixture
def fake_redis(monkeypatch) -> _FakeRedisClient:
    client = _FakeRedisClient()
    monkeypatch.setattr(investigation, "get_client", lambda: client)
    return client


@pytest.mark.asyncio
async def test_save_and_get_context_round_trips(fake_redis):
    await save_context("tenant-a", "session-1", Intent.AUTH_FAILURES, {"host_id": "DESKTOP-042"})

    context = await get_context("tenant-a", "session-1")

    assert context.intent == Intent.AUTH_FAILURES
    assert context.params == {"host_id": "DESKTOP-042"}


@pytest.mark.asyncio
async def test_get_context_returns_none_when_no_session_exists(fake_redis):
    assert await get_context("tenant-a", "never-started") is None


@pytest.mark.asyncio
async def test_save_context_sets_the_configured_idle_ttl(fake_redis):
    await save_context("tenant-a", "session-1", Intent.TOP_ALERTS, {})

    key, ex = fake_redis.set_calls[0]
    assert key == "investigation:session:tenant-a:session-1"
    assert ex == settings.INVESTIGATION_SESSION_TTL_SECONDS


@pytest.mark.asyncio
async def test_sessions_are_isolated_per_tenant(fake_redis):
    await save_context("tenant-a", "session-1", Intent.AUTH_FAILURES, {"host_id": "X"})

    assert await get_context("tenant-b", "session-1") is None


async def _turn(query: str, session_id: str = "session-1", tenant_id: str = "tenant-a"):
    """
    One chat turn the way the router runs it: resolve, then commit the
    context only if the turn would call a tool (i.e. the tool succeeded).
    Returns (intent, params) for the existing assertions.
    """
    resolution = await resolve_query(tenant_id, session_id, query)
    if resolution.kind == QueryResolution.TOOL:
        await commit_context(tenant_id, session_id, resolution.intent, resolution.params)
    return resolution.intent, resolution.params


# ── SS-046 AC: a two-turn conversation resolves the second query using
# context from the first ("show failed logins for host X" -> "what about
# yesterday?") ──

@pytest.mark.asyncio
async def test_follow_up_query_inherits_intent_and_host_id_from_the_first_turn(fake_redis):
    intent1, params1 = await _turn("Show failed logins for host DESKTOP-042")
    assert intent1 == Intent.AUTH_FAILURES
    assert params1 == {"host_id": "DESKTOP-042"}

    intent2, params2 = await _turn("What about yesterday?")

    assert intent2 == Intent.AUTH_FAILURES
    assert params2["host_id"] == "DESKTOP-042"
    assert {"start", "end"} <= params2.keys()


@pytest.mark.asyncio
async def test_a_query_that_classifies_on_its_own_is_treated_as_a_fresh_turn(fake_redis):
    await _turn("Show failed logins for host DESKTOP-042")

    intent, params = await _turn("Which endpoints are riskiest right now?")

    assert intent == Intent.RISKY_ENDPOINTS
    assert params == {}


@pytest.mark.asyncio
async def test_a_follow_up_with_no_prior_session_stays_unknown(fake_redis):
    intent, params = await _turn(session_id="brand-new-session", query="What about yesterday?")

    assert intent == Intent.UNKNOWN
    assert params == {}


@pytest.mark.asyncio
async def test_resolve_query_refreshes_the_session_for_further_follow_ups(fake_redis):
    """A chain of 3 follow-ups keeps resolving to the same subject."""
    await _turn("Show failed logins for host DESKTOP-042")
    await _turn("What about yesterday?")
    intent, params = await _turn("and the day before?")

    assert intent == Intent.AUTH_FAILURES
    assert params["host_id"] == "DESKTOP-042"


@pytest.mark.asyncio
async def test_a_fresh_turn_naming_no_host_has_empty_params(fake_redis):
    intent, params = await _turn("Which endpoints are riskiest right now?")

    assert intent == Intent.RISKY_ENDPOINTS
    assert params == {}


# ── Regression: conversational noise must not inherit stale context ──
#
# Reported live: asking "Which user has the most amount of failed
# logins?" then sending "Hello" made the assistant answer "Hello" with
# the *previous* turn's auth-failures result. Root cause traced to
# resolve_query()'s follow-up-inheritance condition
# (`if intent == Intent.UNKNOWN and previous is not None`) being true
# for *any* unclassifiable text with a live session — not just genuine
# topic-less follow-ups like "what about yesterday?" (SS-046's own
# worked example), which is indistinguishable from a greeting purely
# by keyword score. Confirmed via a live browser repro (Network tab:
# exactly one POST /api/v1/investigate per message, each with the
# correct query text — so this is a backend resolution bug, not a
# frontend duplicate-request or duplicate-render bug).

@pytest.mark.asyncio
async def test_a_greeting_after_a_real_query_does_not_inherit_the_previous_intent(fake_redis):
    """The exact live reproduction: a real query, then a bare greeting."""
    intent1, _ = await _turn("Which user has the most amount of failed logins?")
    assert intent1 == Intent.AUTH_FAILURES  # sanity check: matches what was actually observed live

    intent2, params2 = await _turn("Hello")

    assert intent2 == Intent.UNKNOWN
    assert params2 == {}


@pytest.mark.asyncio
async def test_common_conversational_noise_never_inherits_context(fake_redis):
    await _turn("Show failed logins for host DESKTOP-042")

    for noise in ["hi", "hey", "thanks", "thank you", "ok", "okay", "bye", "Hello!"]:
        intent, params = await _turn(noise)
        assert intent == Intent.UNKNOWN, f"{noise!r} incorrectly inherited context"
        assert params == {}


@pytest.mark.asyncio
async def test_a_greeting_does_not_clobber_saved_context_for_a_later_real_follow_up(fake_redis):
    """
    A greeting sent mid-conversation shouldn't erase the ability for a
    *later*, genuine follow-up to still resolve against the real topic.
    """
    await _turn("Show failed logins for host DESKTOP-042")
    await _turn("Hello")

    intent, params = await _turn("What about yesterday?")

    assert intent == Intent.AUTH_FAILURES
    assert params["host_id"] == "DESKTOP-042"


@pytest.mark.asyncio
async def test_a_genuine_topic_less_follow_up_still_inherits_context_as_before(fake_redis):
    """Non-regression: SS-046's own worked example must keep working."""
    await _turn("Show failed logins for host DESKTOP-042")

    intent, params = await _turn("What about yesterday?")

    assert intent == Intent.AUTH_FAILURES
    assert params["host_id"] == "DESKTOP-042"


# ── SS-089: broader follow-up entity extraction ────────────────────

def test_extract_entities_finds_an_ip_address():
    assert investigation._extract_entities("What activity came from IP 45.33.32.156?") == {"ip": "45.33.32.156"}


def test_extract_entities_finds_a_named_user():
    assert investigation._extract_entities("Show activity for user admin") == {"user": "admin"}
    # This phrasing also names a relative-time phrase ("today") — both are legitimately extracted.
    assert investigation._extract_entities("What did user john.doe do today?", now=datetime(2026, 10, 22, 15, 30, tzinfo=timezone.utc)) == {
        "user": "john.doe", "timerange_hours": 24, "start": "2026-10-22T00:00:00Z"
    }


def test_extract_entities_does_not_mistake_a_question_word_for_a_username():
    """
    Regression, found while designing the extractor: 'Which user HAS...'
    naively captures 'has' as if it were a username. The fix rejects a
    small set of auxiliary/question words that can follow "user"
    without naming anyone.
    """
    assert "user" not in investigation._extract_entities("Which user has the most failed logins?")
    assert "user" not in investigation._extract_entities("What did this user do on DESKTOP-042?")


def test_extract_entities_finds_a_severity_word():
    assert investigation._extract_entities("Show me critical alerts") == {"severity": "critical"}


def test_extract_entities_does_not_match_severity_inside_a_longer_word():
    """'highest' must not be mistaken for the severity 'high' — word-boundary matching."""
    assert investigation._extract_entities("What are the highest priority alerts?") == {}


def test_extract_entities_finds_a_relative_time_phrase():
    assert investigation._extract_entities("Show failed logins from the last hour") == {"timerange_hours": 1}
    assert investigation._extract_entities("What happened today?", now=datetime(2026, 10, 22, 15, 30, tzinfo=timezone.utc)) == {
        "timerange_hours": 24, "start": "2026-10-22T00:00:00Z"
    }
    # 22 Oct 2026 is a Thursday; the week starts Monday 19 Oct (UTC).
    assert investigation._extract_entities("Anything this week?", now=datetime(2026, 10, 22, 15, 30, tzinfo=timezone.utc)) == {
        "timerange_hours": 24 * 7, "start": "2026-10-19T00:00:00Z"
    }


def test_extract_entities_finds_a_numeric_relative_time_phrase():
    assert investigation._extract_entities("Show alerts from the last 6 hours") == {"timerange_hours": 6}
    assert investigation._extract_entities("What happened in the past 12 hours?") == {"timerange_hours": 12}


def test_extract_entities_resolves_yesterday_to_a_bounded_utc_window():
    """
    'yesterday' is a bounded window [yesterday 00:00, today 00:00) UTC,
    passed as start/end. timerange_hours covers the whole window (48h)
    until the tools honour start/end, so nothing is cut short.
    """
    assert investigation._extract_entities("What about yesterday?", now=datetime(2026, 10, 22, 15, 30, tzinfo=timezone.utc)) == {
        "timerange_hours": 48, "start": "2026-10-21T00:00:00Z", "end": "2026-10-22T00:00:00Z",
    }


def test_extract_entities_returns_empty_for_a_query_naming_no_entities():
    assert investigation._extract_entities("Which endpoints are riskiest right now?") == {}


@pytest.mark.asyncio
async def test_a_fresh_turn_naming_an_ip_captures_it(fake_redis):
    intent, params = await _turn("What activity came from IP 45.33.32.156?")

    assert intent == Intent.IP_ACTIVITY
    assert params["ip"] == "45.33.32.156"


@pytest.mark.asyncio
async def test_a_fresh_turn_naming_a_severity_captures_it(fake_redis):
    intent, params = await _turn("Show me the most critical alerts")

    assert intent == Intent.TOP_ALERTS
    assert params == {"severity": "critical"}


@pytest.mark.asyncio
async def test_a_follow_up_naming_a_new_severity_overrides_the_inherited_one(fake_redis):
    await _turn("Show me the most critical alerts")

    intent, params = await _turn("What about high severity ones?")

    assert intent == Intent.TOP_ALERTS
    assert params["severity"] == "high"


@pytest.mark.asyncio
async def test_a_follow_up_naming_a_user_adds_it_to_the_inherited_params(fake_redis):
    await _turn("Show failed logins for host DESKTOP-042")

    intent, params = await _turn("What about for user admin?")

    assert intent == Intent.AUTH_FAILURES
    assert params == {"host_id": "DESKTOP-042", "user": "admin"}


@pytest.mark.asyncio
async def test_a_follow_up_naming_a_time_window_keeps_the_inherited_host(fake_redis):
    """A follow-up that only names a time keeps the previous turn's intent and host."""
    await _turn("Show failed logins for host DESKTOP-042")

    intent, params = await _turn("What about yesterday?")

    assert intent == Intent.AUTH_FAILURES
    assert params["host_id"] == "DESKTOP-042"


# ── SS-087: bounded conversation transcript ────────────────────────

@pytest.mark.asyncio
async def test_save_and_get_context_round_trips_a_transcript(fake_redis):
    transcript = [{"query": "failed logins?", "answer": "Found 3."}]
    await save_context("tenant-a", "session-1", Intent.AUTH_FAILURES, {}, transcript)

    context = await get_context("tenant-a", "session-1")

    assert context.transcript == transcript


@pytest.mark.asyncio
async def test_save_context_without_a_transcript_defaults_to_empty(fake_redis):
    """Existing call sites that don't pass transcript must keep working (backward compatibility)."""
    await save_context("tenant-a", "session-1", Intent.TOP_ALERTS, {})

    context = await get_context("tenant-a", "session-1")
    assert context.transcript == []


@pytest.mark.asyncio
async def test_append_turn_adds_a_query_answer_pair_to_the_transcript(fake_redis):
    await _turn("Show failed logins for host DESKTOP-042")

    await append_turn("tenant-a", "session-1", "Show failed logins for host DESKTOP-042", "Found 3 failed logins.")

    context = await get_context("tenant-a", "session-1")
    assert context.transcript == [
        {"query": "Show failed logins for host DESKTOP-042", "answer": "Found 3 failed logins."}
    ]


@pytest.mark.asyncio
async def test_append_turn_caps_the_transcript_dropping_the_oldest_first(fake_redis):
    await _turn("Show failed logins for host DESKTOP-042")

    for i in range(MAX_TRANSCRIPT_TURNS + 2):
        await append_turn("tenant-a", "session-1", f"query {i}", f"answer {i}")

    context = await get_context("tenant-a", "session-1")
    assert len(context.transcript) == MAX_TRANSCRIPT_TURNS
    # Oldest (query 0, query 1) dropped; the most recent MAX_TRANSCRIPT_TURNS survive, in order.
    assert context.transcript[0]["query"] == "query 2"
    assert context.transcript[-1]["query"] == f"query {MAX_TRANSCRIPT_TURNS + 1}"


@pytest.mark.asyncio
async def test_append_turn_is_a_noop_when_no_session_exists(fake_redis):
    await append_turn("tenant-a", "never-started", "some query", "some answer")

    assert await get_context("tenant-a", "never-started") is None
    assert fake_redis.set_calls == []  # nothing was written


@pytest.mark.asyncio
async def test_committing_the_next_turn_preserves_a_transcript_built_by_append_turn(fake_redis):
    """
    Regression: committing the next turn's intent/params must not wipe
    out a transcript append_turn() already built — both write the same
    session key.
    """
    await _turn("Show failed logins for host DESKTOP-042")
    await append_turn("tenant-a", "session-1", "Show failed logins for host DESKTOP-042", "Found 3.")

    await _turn("What about yesterday?")

    context = await get_context("tenant-a", "session-1")
    assert context.transcript == [{"query": "Show failed logins for host DESKTOP-042", "answer": "Found 3."}]
