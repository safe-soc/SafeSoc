"""
SafeSOC — Investigation Service Tests
"""

import pytest

from app.core.config import settings
from app.core.enums import Intent
from app.services import investigation
from app.services.investigation import (
    INTENT_CLASSIFICATION_ACCURACY_THRESHOLD,
    classify_intent,
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


# ── SS-046 AC: a two-turn conversation resolves the second query using
# context from the first ("show failed logins for host X" -> "what about
# yesterday?") ──

@pytest.mark.asyncio
async def test_follow_up_query_inherits_intent_and_host_id_from_the_first_turn(fake_redis):
    intent1, params1 = await resolve_query("tenant-a", "session-1", "Show failed logins for host DESKTOP-042")
    assert intent1 == Intent.AUTH_FAILURES
    assert params1 == {"host_id": "DESKTOP-042"}

    intent2, params2 = await resolve_query("tenant-a", "session-1", "What about yesterday?")

    assert intent2 == Intent.AUTH_FAILURES
    assert params2 == {"host_id": "DESKTOP-042"}


@pytest.mark.asyncio
async def test_a_query_that_classifies_on_its_own_is_treated_as_a_fresh_turn(fake_redis):
    await resolve_query("tenant-a", "session-1", "Show failed logins for host DESKTOP-042")

    intent, params = await resolve_query("tenant-a", "session-1", "Which endpoints are riskiest right now?")

    assert intent == Intent.RISKY_ENDPOINTS
    assert params == {}


@pytest.mark.asyncio
async def test_a_follow_up_with_no_prior_session_stays_unknown(fake_redis):
    intent, params = await resolve_query("tenant-a", "brand-new-session", "What about yesterday?")

    assert intent == Intent.UNKNOWN
    assert params == {}


@pytest.mark.asyncio
async def test_resolve_query_refreshes_the_session_for_further_follow_ups(fake_redis):
    """A chain of 3 follow-ups keeps resolving to the same subject."""
    await resolve_query("tenant-a", "session-1", "Show failed logins for host DESKTOP-042")
    await resolve_query("tenant-a", "session-1", "What about yesterday?")
    intent, params = await resolve_query("tenant-a", "session-1", "and the day before?")

    assert intent == Intent.AUTH_FAILURES
    assert params == {"host_id": "DESKTOP-042"}


@pytest.mark.asyncio
async def test_a_fresh_turn_naming_no_host_has_empty_params(fake_redis):
    intent, params = await resolve_query("tenant-a", "session-1", "Which endpoints are riskiest right now?")

    assert intent == Intent.RISKY_ENDPOINTS
    assert params == {}
