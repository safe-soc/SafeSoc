"""
SafeSOC — Investigate Chat: Fixes From the 30-Question Live Run
Each section is one issue from the live transcript and backend logs:

1. Groq 429s became anonymous fallbacks — now retried once when the
   wait fits the budget, otherwise reported as rate_limited, and every
   fallback is a useful sentence built from the data.
2. A "yesterday" window stuck to later follow-ups about other subjects.
3. "Was the attack successful?" denied a login the host's open
   Successful-compromise incident records.
4. "List privilege escalation events" searched every alert.
5. Zero results came back as "Found 0 result(s)…".
6. Counts came from the sample, not the full match set.
7. "Top 3" returning 3 was flagged partial.
8. A deleted user's still-signed token was accepted.
9. Numbers in dates/times/IPs tripped the grounding check; a real
   ungrounded number now gets the templated answer instead.
"""

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, Mock

import pytest
import requests
from starlette.websockets import WebSocketDisconnect

from app.clients import groq, ollama
from app.core import dependencies
from app.core.config import settings
from app.core.enums import CorrelationPattern, FallbackReason, Intent, IncidentStatus, QueryResolution, RiskLevel, UserRole
from app.db.postgresql import get_db
from app.main import app
from app.mcp.tools import TOOLS, AlertListOutput, EndpointSnapshotOutput, RiskyEndpointsOutput
from app.models.endpoint import Endpoint
from app.models.incident import Incident
from app.routers.v1 import investigate as investigate_router
from app.routers.v1.investigate import _answer_appears_grounded, _empty_result_answer, _fallback_answer
from app.services import investigation
from app.services.investigation import commit_context, resolve_query
from tests.test_investigate_resolution import KNOWN, NOW
from tests.test_investigation import _FakeRedisClient

TENANT = uuid.uuid4()
# Captured at import, before conftest's autouse stub replaces it per test.
REAL_USER_EXISTS = dependencies.user_exists


@pytest.fixture
def fake_redis(monkeypatch):
    client = _FakeRedisClient()
    monkeypatch.setattr(investigation, "get_client", lambda: client)
    return client


@pytest.fixture(autouse=True)
def _no_incidents(monkeypatch):
    monkeypatch.setattr("app.mcp.tools.list_incidents", AsyncMock(return_value=([], 0)))


@pytest.fixture
def router_env(monkeypatch, fake_redis):
    async def override_get_db():
        yield "fake-db-session"

    app.dependency_overrides[get_db] = override_get_db
    monkeypatch.setattr("app.routers.v1.investigate.get_known_entities", AsyncMock(return_value=KNOWN))
    monkeypatch.setattr("app.routers.v1.investigate.record_event", AsyncMock())
    yield
    app.dependency_overrides.pop(get_db, None)


def _search_stub(by_action=None, default=None):
    default = default or {"total": 0, "alerts": [], "counts": {}}

    async def fake(**kwargs):
        return (by_action or {}).get(kwargs.get("action"), default)

    return AsyncMock(side_effect=fake)


# ── 1. Rate limiting and useful fallbacks ────────────────────────────

class _Response:
    def __init__(self, status_code, headers=None, text="ok"):
        self.status_code = status_code
        self.headers = headers or {}
        self._text = text

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code} Client Error")

    def json(self):
        return {"choices": [{"message": {"content": self._text}}]}


@pytest.fixture
def groq_key(monkeypatch):
    monkeypatch.setattr(groq.settings, "GROQ_API_KEY", "test-key")
    monkeypatch.setattr(groq.settings, "GROQ_MODEL", "llama-3.1-8b-instant")


def test_groq_retries_a_429_once_when_retry_after_fits_the_budget(monkeypatch, groq_key):
    post = Mock(side_effect=[_Response(429, {"retry-after": "2"}), _Response(200, text="answer")])
    sleep = Mock()
    monkeypatch.setattr(groq.requests, "post", post)
    monkeypatch.setattr(groq.time, "sleep", sleep)

    assert groq.generate("p", 100, time_budget_seconds=10) == "answer"
    sleep.assert_called_once_with(2.0)
    assert post.call_count == 2


def test_groq_uses_the_reset_headers_when_there_is_no_retry_after(monkeypatch, groq_key):
    post = Mock(side_effect=[
        _Response(429, {"x-ratelimit-reset-requests": "1.5s", "x-ratelimit-reset-tokens": "250ms"}),
        _Response(200, text="answer"),
    ])
    sleep = Mock()
    monkeypatch.setattr(groq.requests, "post", post)
    monkeypatch.setattr(groq.time, "sleep", sleep)

    groq.generate("p", 100, time_budget_seconds=10)

    sleep.assert_called_once_with(1.5)  # the longer of the two resets


@pytest.mark.parametrize("headers, budget", [
    ({"retry-after": "30"}, 10),   # wait longer than the budget
    ({"retry-after": "9"}, 10),    # wait + request margin doesn't fit
    ({}, 10),                      # no wait given at all
    ({"retry-after": "1"}, None),  # caller gave no budget
])
def test_groq_raises_rate_limited_without_retrying_when_the_wait_does_not_fit(monkeypatch, groq_key, headers, budget):
    post = Mock(return_value=_Response(429, headers))
    monkeypatch.setattr(groq.requests, "post", post)
    monkeypatch.setattr(groq.time, "sleep", Mock())

    with pytest.raises(groq.GroqRateLimitError):
        groq.generate("p", 100, time_budget_seconds=budget)
    assert post.call_count == 1


def test_groq_gives_up_after_one_retry(monkeypatch, groq_key):
    post = Mock(return_value=_Response(429, {"retry-after": "1"}))
    monkeypatch.setattr(groq.requests, "post", post)
    monkeypatch.setattr(groq.time, "sleep", Mock())

    with pytest.raises(groq.GroqRateLimitError):
        groq.generate("p", 100, time_budget_seconds=10)
    assert post.call_count == 2


def test_a_rate_limited_answer_is_flagged_rate_limited_with_a_useful_fallback(client, make_auth_headers, monkeypatch, router_env):
    monkeypatch.setattr(settings, "LLM_PROVIDER", "groq")
    monkeypatch.setattr(groq, "generate", Mock(side_effect=groq.GroqRateLimitError("429", 30.0)))
    result = AlertListOutput(
        subject="failed logins on WIN10-FIN-07 in the last 24 hours", total=6, alerts=[],
        counts={"Source IPs (where the activity came from)": {"203.0.113.25": 4, "198.51.100.2": 2}},
    )
    monkeypatch.setattr("app.routers.v1.investigate.TOOLS", {Intent.AUTH_FAILURES: Mock(call=AsyncMock(return_value=result))})

    body = client.post(
        "/api/v1/investigate", json={"query": "Show failed logins for WIN10-FIN-07"},
        headers=make_auth_headers(tenant_id=TENANT),
    ).json()

    assert body["is_fallback"] is True
    assert body["fallback_reason"] == "rate_limited"
    assert body["answer"] == (
        "Failed logins on WIN10-FIN-07 in the last 24 hours: 6. "
        "Source IPs (where the activity came from): 203.0.113.25 (4), 198.51.100.2 (2)."
    )


def _incident_dict(label, host, severity, confidence, status="open"):
    return {"category_label": label, "hosts": [host], "severity": severity, "confidence": confidence,
            "status": status, "alert_count": 2}


def test_every_fallback_is_a_sentence_from_the_data_never_found_n_results():
    from app.mcp.tools import AttackChainStatusOutput, OverviewOutput

    chains = AttackChainStatusOutput(total=5, active_count=4, incidents=[
        _incident_dict("Privilege escalation", "PRIV-TEST-01", "critical", 0.95),
        _incident_dict("Credential brute force", "TEST-A1", "medium", 0.64, "investigating"),
        _incident_dict("Successful compromise", "UBUNTU-WEB-01", "medium", 0.64, "investigating"),
        _incident_dict("Credential brute force", "WIN10-FIN-07", "medium", 0.64, "investigating"),
        _incident_dict("Data exfiltration", "DESKTOP-032", "high", 0.8, "resolved"),
    ])
    assert _fallback_answer(Intent.ATTACK_CHAIN_STATUS, chains) == (
        "4 active attack chains: Privilege escalation on PRIV-TEST-01 (critical, 95%); "
        "Credential brute force on TEST-A1 (medium, 64%); Successful compromise on UBUNTU-WEB-01 (medium, 64%); "
        "Credential brute force on WIN10-FIN-07 (medium, 64%). 1 more is resolved or false positive."
    )

    overview = OverviewOutput(
        subject="alerts in the last 24 hours", total_alerts=170, counts={"Severity": {"low": 98, "critical": 1}},
        critical_high_total=35, active_incident_count=1,
        active_incidents=[_incident_dict("Privilege escalation", "PRIV-TEST-01", "critical", 0.95)],
    )
    assert _fallback_answer(Intent.OVERVIEW, overview) == (
        "Alerts in the last 24 hours: 170. By severity: low (98), critical (1). Critical or high: 35. "
        "1 active attack chain: Privilege escalation on PRIV-TEST-01 (critical, 95%)."
    )

    risky = RiskyEndpointsOutput(endpoints=[{"host_id": "H1", "risk_score": 90, "risk_level": "critical"}])
    assert _fallback_answer(Intent.RISKY_ENDPOINTS, risky) == "Riskiest endpoints: H1 (risk 90, critical)."

    for result, intent in ((chains, Intent.ATTACK_CHAIN_STATUS), (overview, Intent.OVERVIEW), (risky, Intent.RISKY_ENDPOINTS)):
        assert "result(s)" not in _fallback_answer(intent, result)


# ── 2. Window stickiness + 3. snapshot consistency ───────────────────

@pytest.mark.asyncio
async def test_a_bounded_window_does_not_stick_to_a_new_subject(fake_redis):
    async def turn(query):
        resolution = await resolve_query("t", "s", query, KNOWN, now=NOW)
        assert resolution.kind == QueryResolution.TOOL, query
        await commit_context("t", "s", resolution.intent, resolution.params)
        return resolution

    first = await turn("Show failed logins for WIN10-FIN-07")
    yesterday = await turn("what about yesterday?")
    users = await turn("which users were involved?")
    new_host = await turn("now show me UBUNTU-WEB-01")
    success = await turn("was the attack successful?")

    assert "start" not in first.params
    assert (yesterday.params["start"], yesterday.params["end"]) == ("2026-10-21T00:00:00Z", "2026-10-22T00:00:00Z")
    # A direct follow-up on the same subject keeps the window it asked for.
    assert users.params["start"] == "2026-10-21T00:00:00Z" and users.params["host_id"] == "WIN10-FIN-07"
    # A new host without a time of its own: back to the default lookback.
    assert new_host.intent == Intent.AUTH_FAILURES and new_host.params["host_id"] == "UBUNTU-WEB-01"
    assert not {"start", "end", "timerange_hours"} & new_host.params.keys()
    # A success question: the host's snapshot over at least the default 24 hours.
    assert success.intent == Intent.ENDPOINT_SNAPSHOT
    assert success.params == {"host_id": "UBUNTU-WEB-01", "timerange_hours": 24}


@pytest.mark.asyncio
async def test_a_new_subject_that_states_a_time_keeps_its_own_time(fake_redis):
    await commit_context("t", "s", Intent.AUTH_FAILURES, {"host_id": "WIN10-FIN-07", "start": "x", "end": "y"})

    resolution = await resolve_query("t", "s", "now UBUNTU-WEB-01 in the last 6 hours", KNOWN, now=NOW)

    assert resolution.params["timerange_hours"] == 6 and "start" not in resolution.params


@pytest.mark.asyncio
async def test_a_success_question_looks_back_at_least_24_hours(fake_redis):
    resolution = await resolve_query("t", "s", "did they get in on UBUNTU-WEB-01 in the last hour?", KNOWN, now=NOW)

    assert resolution.intent == Intent.ENDPOINT_SNAPSHOT
    assert resolution.params["timerange_hours"] == 24


def _alert(action, minute, ip, host="UBUNTU-WEB-01", user="jane.smith", alert_id=None):
    ts = (datetime(2026, 10, 22, 11, 0, tzinfo=timezone.utc) + timedelta(minutes=minute)).isoformat()
    return {"alert_id": alert_id or f"{action}-{minute}", "action": action, "timestamp": ts,
            "source_ip": ip, "user": user, "host_id": host}


@pytest.mark.asyncio
async def test_snapshot_reports_the_success_from_a_compromise_incident_outside_the_window(
    monkeypatch, _mock_incident_summary_lookup
):
    """
    The live contradiction: the searched window held no login_success, but
    the host's open Successful-compromise incident does. The snapshot
    evaluates the incident's own alerts too, and never says "no login
    succeeded".
    """
    incident_alerts = [_alert("failed_login", m, f"198.51.100.{m}", alert_id=f"f{m}") for m in range(6)]
    incident_alerts.append(_alert("login_success", 7, "198.51.100.18", alert_id="s1"))
    incident = Incident(
        id=uuid.uuid4(), tenant_id=TENANT, status=IncidentStatus.INVESTIGATING,
        category=CorrelationPattern.SUCCESSFUL_COMPROMISE, confidence=0.64,
        alert_ids=[a["alert_id"] for a in incident_alerts], tags=[],
        created_at=datetime.now(timezone.utc), updated_at=datetime.now(timezone.utc),
    )
    monkeypatch.setattr("app.mcp.tools.list_incidents", AsyncMock(return_value=([incident], 1)))
    _mock_incident_summary_lookup.return_value = incident_alerts
    by_ids = AsyncMock(return_value=incident_alerts)
    monkeypatch.setattr("app.mcp.tools.get_alerts_by_ids", by_ids)
    monkeypatch.setattr("app.mcp.tools.search_alerts", _search_stub())  # nothing in the searched window
    monkeypatch.setattr("app.mcp.tools.get_endpoint", AsyncMock(return_value=None))

    result = await TOOLS[Intent.ENDPOINT_SNAPSHOT].call(None, TENANT, {"host_id": "UBUNTU-WEB-01", "timerange_hours": 24})

    assert result.compromise_incident_open is True
    assert result.successful_login_after_failures is True
    assert result.logins_after_failures[0]["failed_attempts_before"] == 6
    assert [i["category_label"] for i in result.open_incidents] == ["Successful compromise"]
    by_ids.assert_awaited_once()
    answer = _fallback_answer(Intent.ENDPOINT_SNAPSHOT, result)
    assert "No login succeeded" not in answer
    assert "A login succeeded after failed attempts: jane.smith from 198.51.100.18, after 6 failed attempts." in answer
    assert _empty_result_answer(result) is None  # the incident means there IS something to say


# ── 4. Activity-type topics ──────────────────────────────────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("query, log_type", [
    ("list privilege escalation events", "privilege"),
    ("any sudo or admin rights changes?", "privilege"),
    ("show outbound connections", "network"),
    ("what commands executed on WIN10-FIN-07?", "process"),
    ("any file changes today?", "file"),
])
async def test_activity_topics_filter_top_alerts_by_log_type(fake_redis, monkeypatch, query, log_type):
    resolution = await resolve_query("t", "s", query, KNOWN, now=NOW)
    assert (resolution.intent, resolution.params["log_type"]) == (Intent.TOP_ALERTS, log_type)

    search = _search_stub(default={"total": 1, "alerts": [{"alert_id": "a"}], "counts": {}})
    monkeypatch.setattr("app.mcp.tools.search_alerts", search)
    result = await TOOLS[Intent.TOP_ALERTS].call(None, TENANT, resolution.params)

    assert search.call_args.kwargs["log_type"] == log_type
    assert search.call_args.kwargs["tenant_id"] == str(TENANT)
    assert f"of type {log_type}" in result.scope


@pytest.mark.asyncio
async def test_lateral_movement_lists_incidents_of_that_pattern(fake_redis, monkeypatch):
    resolution = await resolve_query("t", "s", "any lateral movement?", KNOWN, now=NOW)
    assert (resolution.intent, resolution.params) == (Intent.ATTACK_CHAIN_STATUS, {"category": "lateral_movement"})

    listing = AsyncMock(return_value=([], 0))
    monkeypatch.setattr("app.mcp.tools.list_incidents", listing)
    result = await TOOLS[Intent.ATTACK_CHAIN_STATUS].call(None, TENANT, resolution.params)

    assert listing.call_args.kwargs["category"] == CorrelationPattern.LATERAL_MOVEMENT
    assert result.scope == "Searched incidents of pattern Lateral movement."
    assert _empty_result_answer(result) == "No incidents of pattern Lateral movement found."


# ── 5. Zero results ──────────────────────────────────────────────────

def test_zero_results_get_a_scope_sentence_and_no_llm_call(client, make_auth_headers, monkeypatch, router_env):
    generate = Mock(return_value="should not be called")
    monkeypatch.setattr(ollama, "generate", generate)
    monkeypatch.setattr("app.mcp.tools.search_alerts", _search_stub())

    body = client.post(
        "/api/v1/investigate", json={"query": "failed logins for john.doe on UBUNTU-WEB-01"},
        headers=make_auth_headers(tenant_id=TENANT),
    ).json()

    assert body["answer"] == "No failed logins for john.doe on UBUNTU-WEB-01 in the last 24 hours."
    assert body["is_fallback"] is False and body["fallback_reason"] is None
    generate.assert_not_called()


# ── 6. Counts are real totals ────────────────────────────────────────

@pytest.mark.asyncio
async def test_counts_are_the_aggregation_totals_not_the_sample(monkeypatch):
    sample = [{"alert_id": f"a{i}", "host_id": "HOST-A", "user": "alice"} for i in range(20)]
    search = _search_stub(default={"total": 500, "alerts": sample, "counts": {
        "host_id": {"HOST-C": 480, "HOST-A": 20}, "user": {"bob": 400, "alice": 100},
        "severity": {"low": 500}, "log_type": {"authentication": 500},
    }})
    monkeypatch.setattr("app.mcp.tools.search_alerts", search)

    result = await TOOLS[Intent.TOP_ALERTS].call(None, TENANT, {})

    assert result.counts["Hosts"] == {"HOST-C": 480, "HOST-A": 20}
    assert result.counts["Accounts targeted or used"] == {"bob": 400, "alice": 100}
    assert result.total == 500 and len(result.alerts) == 20


# ── 7. truncated means "left out more than was asked for" ────────────

@pytest.mark.asyncio
@pytest.mark.parametrize("params, expected_count, truncated", [
    ({"limit": 3}, 3, False),   # asked for the top 3, got 3
    ({}, 10, True),             # asked for no number: the default 10 of 15 is partial
])
async def test_risky_truncated_only_when_more_was_left_out_than_asked(monkeypatch, params, expected_count, truncated):
    now = datetime.now(timezone.utc)
    endpoints = [Endpoint(id=uuid.uuid4(), tenant_id=TENANT, host_id=f"H{i}", risk_score=99 - i,
                          risk_level=RiskLevel.HIGH, updated_at=now) for i in range(15)]
    monkeypatch.setattr("app.mcp.tools.list_endpoints", AsyncMock(return_value=endpoints))

    result = await TOOLS[Intent.RISKY_ENDPOINTS].call(None, TENANT, params)

    assert (len(result.endpoints), result.truncated) == (expected_count, truncated)


# ── 8. Deleted-user tokens ───────────────────────────────────────────

def test_a_token_for_a_deleted_user_is_rejected_with_401(client, make_auth_headers, _token_users_exist):
    _token_users_exist.return_value = False

    response = client.get("/api/v1/incidents", headers=make_auth_headers())

    assert response.status_code == 401


def test_a_deleted_users_token_cannot_be_refreshed(client, make_auth_headers, _token_users_exist):
    _token_users_exist.return_value = False
    token = make_auth_headers()["Authorization"].split()[1]

    response = client.post("/api/v1/auth/refresh", json={"token": token})

    assert response.status_code == 401


def test_a_deleted_users_websocket_is_closed(client, make_auth_headers, _token_users_exist):
    _token_users_exist.return_value = False
    token = make_auth_headers()["Authorization"].split()[1]

    with pytest.raises(WebSocketDisconnect) as closed:
        with client.websocket_connect(f"/ws?token={token}"):
            pass
    assert closed.value.code == 1008


class _UserDb:
    def __init__(self, user):
        self.user = user
        self.lookups = 0

    async def get(self, model, key):
        self.lookups += 1
        return self.user

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


@pytest.mark.asyncio
async def test_user_exists_checks_the_tenant_and_caches_briefly(monkeypatch):
    """The real check (conftest stubs it for every other test): PK lookup, tenant match, short cache."""
    tenant, other_tenant, user_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    db = _UserDb(Mock(tenant_id=tenant))
    monkeypatch.setattr(dependencies, "async_session_factory", lambda: db)
    dependencies._user_check_cache.clear()
    try:
        assert await REAL_USER_EXISTS(tenant, user_id) is True
        assert await REAL_USER_EXISTS(tenant, user_id) is True
        assert db.lookups == 1  # the second call is served from the short cache
        assert await REAL_USER_EXISTS(other_tenant, user_id) is False  # a user of another tenant

        db.user = None
        dependencies._user_check_cache.clear()
        assert await REAL_USER_EXISTS(tenant, user_id) is False  # deleted
    finally:
        dependencies._user_check_cache.clear()


# ── 9. Grounding check ───────────────────────────────────────────────

def test_dates_times_ips_and_list_markers_are_not_checked():
    result = AlertListOutput(subject="failed logins in the last 24 hours", total=6, alerts=[])

    answer = (
        "1. 6 failed logins in the last 24 hours, the first at 11:03:31 on 2026-10-23 "
        "(22 Oct 2026) from 203.0.113.25."
    )

    assert _answer_appears_grounded(answer, result)


def test_numbers_from_the_question_count_as_grounded():
    result = RiskyEndpointsOutput(endpoints=[{"host_id": "H1", "risk_score": 90, "risk_level": "critical"}])

    assert _answer_appears_grounded("Here are the top 3: H1 (90).", result, query="top 3 risky machines")


def test_an_ungrounded_answer_is_replaced_by_the_templated_one(client, make_auth_headers, monkeypatch, router_env):
    monkeypatch.setattr(ollama, "generate", Mock(return_value="There were 999 failed logins."))
    result = AlertListOutput(subject="failed logins in the last 24 hours", total=6, alerts=[])
    monkeypatch.setattr("app.routers.v1.investigate.TOOLS", {Intent.AUTH_FAILURES: Mock(call=AsyncMock(return_value=result))})

    body = client.post(
        "/api/v1/investigate", json={"query": "show me failed logins"}, headers=make_auth_headers(tenant_id=TENANT),
    ).json()

    assert body["answer"] == "Failed logins in the last 24 hours: 6."
    assert (body["is_fallback"], body["fallback_reason"]) == (True, "ungrounded")
