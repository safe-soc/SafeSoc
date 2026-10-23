"""
SafeSOC — Investigation Router Tests
"""

import time
import uuid
from unittest.mock import AsyncMock, Mock

import pytest
from opensearchpy.exceptions import OpenSearchException

from app.core.enums import Intent, QueryResolution, UserRole
from app.core.security import create_access_token
from app.db.postgresql import get_db
from app.main import app
from app.mcp.tools import AlertListOutput, EndpointSnapshotOutput, RiskyEndpointsOutput
from app.services.investigation import UNKNOWN_INTENT_ANSWER, ConversationContext, KnownEntities, Resolution


def _mock_resolve_query(monkeypatch, intent, params=None):
    """UNKNOWN resolves to the help text; any other intent to a tool call."""
    if intent == Intent.UNKNOWN:
        resolution = Resolution(kind=QueryResolution.UNKNOWN, intent=intent, message=UNKNOWN_INTENT_ANSWER)
    else:
        resolution = Resolution(kind=QueryResolution.TOOL, intent=intent, params=params or {})
    monkeypatch.setattr("app.routers.v1.investigate.resolve_query", AsyncMock(return_value=resolution))


def _headers_for(tenant_id: uuid.UUID, user_id: uuid.UUID, role: UserRole = UserRole.ANALYST) -> dict:
    """
    Like make_auth_headers, but exposes the exact user_id used — needed
    to assert record_event()'s actor_user_id came from the authenticated
    user specifically (SS-098), which make_auth_headers's own randomly-
    generated user_id can't prove.
    """
    token = create_access_token(tenant_id, user_id, role)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(autouse=True)
def db_session():
    """
    Every test here mocks TOOLS[intent].call entirely, so the fake
    session is never actually queried — this override just avoids
    depending on a real Postgres connection being reachable, matching
    the pattern in tests/test_incidents_router.py.
    """
    async def override_get_db():
        yield "fake-db-session"

    app.dependency_overrides[get_db] = override_get_db
    yield
    app.dependency_overrides.pop(get_db, None)


@pytest.fixture(autouse=True)
def _mock_investigation_context(monkeypatch):
    """
    SS-088: the router now calls get_context()/append_turn() directly
    (not just resolve_query(), which every test here already mocks) on
    every successful request — without this, those calls would hit a
    real, unavailable Redis connection. Defaults to "no transcript,
    nothing recorded" so existing tests see unchanged behavior; tests
    that care about transcript content override these explicitly.

    SS-098: record_event() is now called at all three return points
    (UNKNOWN, tool-error, success) — same rationale, but against real
    Postgres instead of Redis. Defaults to a no-op AsyncMock; tests
    that care about the audit call override it explicitly.
    """
    monkeypatch.setattr("app.routers.v1.investigate.get_context", AsyncMock(return_value=None))
    monkeypatch.setattr("app.routers.v1.investigate.append_turn", AsyncMock())
    monkeypatch.setattr("app.routers.v1.investigate.record_event", AsyncMock())
    # Known-entity lookup (Redis + OpenSearch + Postgres) and the
    # context writes are no-ops here; test_investigate_resolution.py
    # covers them.
    monkeypatch.setattr("app.routers.v1.investigate.get_known_entities", AsyncMock(return_value=KnownEntities()))
    monkeypatch.setattr("app.routers.v1.investigate.commit_context", AsyncMock())
    monkeypatch.setattr("app.routers.v1.investigate.remember_clarification", AsyncMock())


def test_investigate_requires_authentication(client):
    response = client.post("/api/v1/investigate", json={"query": "show me failed logins"})

    assert response.status_code == 401


def test_investigate_returns_a_defined_fallback_for_an_unclassifiable_query(client, auth_headers, monkeypatch):
    _mock_resolve_query(monkeypatch, Intent.UNKNOWN)

    response = client.post("/api/v1/investigate", json={"query": "what's the weather?"}, headers=auth_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["intent"] == "unknown"
    assert body["data"] == {}
    assert body["answer"]  # a real, non-empty message — not a silent wrong answer
    assert body["is_fallback"] is False  # not a degraded answer — this is the designed "I don't understand" response


def test_investigate_calls_the_matching_tool_and_returns_its_data(client, auth_headers, monkeypatch):
    _mock_resolve_query(monkeypatch, Intent.AUTH_FAILURES, {"host_id": "DESKTOP-042"})
    mock_tool_call = AsyncMock(return_value=AlertListOutput(total=2, alerts=[{"alert_id": "a1"}, {"alert_id": "a2"}]))
    monkeypatch.setattr("app.routers.v1.investigate.TOOLS", {Intent.AUTH_FAILURES: Mock(call=mock_tool_call)})
    monkeypatch.setattr(
        "app.routers.v1.investigate._generate_answer", AsyncMock(return_value=("Found 2 failed logins.", False))
    )

    response = client.post(
        "/api/v1/investigate", json={"query": "failed logins for DESKTOP-042"}, headers=auth_headers
    )

    assert response.status_code == 200
    body = response.json()
    assert body["intent"] == "auth_failures"
    assert body["answer"] == "Found 2 failed logins."
    assert body["data"]["total"] == 2
    assert body["is_fallback"] is False
    mock_tool_call.assert_called_once()


def test_investigate_returns_is_fallback_false_for_a_genuine_llm_answer(client, auth_headers, monkeypatch):
    """
    SS-084: a genuine (non-degraded) LLM answer, exercised through the
    real _generate_answer path (only the LLM client itself is mocked),
    must come back with is_fallback: false.
    """
    _mock_resolve_query(monkeypatch, Intent.TOP_ALERTS)
    mock_tool_call = AsyncMock(return_value=AlertListOutput(total=5, alerts=[]))
    monkeypatch.setattr("app.routers.v1.investigate.TOOLS", {Intent.TOP_ALERTS: Mock(call=mock_tool_call)})

    from app.clients import ollama
    monkeypatch.setattr(ollama, "generate", Mock(return_value="You have 5 top alerts right now."))

    response = client.post("/api/v1/investigate", json={"query": "top alerts"}, headers=auth_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["answer"] == "You have 5 top alerts right now."
    assert body["is_fallback"] is False


# ── SS-088: conversation transcript fed into the LLM prompt ───────

@pytest.mark.asyncio
async def test_generate_answer_includes_transcript_history_in_the_prompt_when_present(monkeypatch):
    from app.routers.v1.investigate import _generate_answer

    mock_generate = Mock(return_value="answer text")
    from app.clients import ollama
    monkeypatch.setattr(ollama, "generate", mock_generate)

    transcript = [{"query": "prior q", "answer": "prior a"}]
    await _generate_answer("current q", Intent.TOP_ALERTS, AlertListOutput(total=1, alerts=[]), transcript)

    prompt = mock_generate.call_args.args[0]
    assert "prior q" in prompt
    assert "prior a" in prompt


@pytest.mark.asyncio
async def test_generate_answer_passes_the_interactive_chat_token_budget(monkeypatch):
    """
    Regression: ollama.generate()/groq.generate() used to read
    INVESTIGATION_LLM_MAX_OUTPUT_TOKENS internally; now each caller
    passes its own budget explicitly. The interactive chat must keep
    using its own (tighter, latency-tuned) setting, not the incident
    narrative's larger one.
    """
    from app.core.config import settings
    from app.routers.v1.investigate import _generate_answer

    mock_generate = Mock(return_value="answer text")
    from app.clients import ollama
    monkeypatch.setattr(ollama, "generate", mock_generate)
    monkeypatch.setattr(settings, "INVESTIGATION_LLM_MAX_OUTPUT_TOKENS", 120)

    await _generate_answer("top alerts", Intent.TOP_ALERTS, AlertListOutput(total=1, alerts=[]), [])

    assert mock_generate.call_args.args[1] == 120


@pytest.mark.asyncio
async def test_generate_answer_omits_the_transcript_section_when_there_is_no_history(monkeypatch):
    from app.routers.v1.investigate import _generate_answer

    mock_generate = Mock(return_value="answer text")
    from app.clients import ollama
    monkeypatch.setattr(ollama, "generate", mock_generate)

    await _generate_answer("current q", Intent.TOP_ALERTS, AlertListOutput(total=1, alerts=[]), [])

    prompt = mock_generate.call_args.args[0]
    assert "Prior conversation" not in prompt


def test_investigate_feeds_transcript_into_the_prompt_and_appends_this_turn(client, make_auth_headers, monkeypatch):
    tenant_id = uuid.uuid4()
    headers = make_auth_headers(tenant_id=tenant_id)
    _mock_resolve_query(monkeypatch, Intent.TOP_ALERTS)
    mock_tool_call = AsyncMock(return_value=AlertListOutput(total=5, alerts=[]))
    monkeypatch.setattr("app.routers.v1.investigate.TOOLS", {Intent.TOP_ALERTS: Mock(call=mock_tool_call)})

    prior_transcript = [{"query": "prior q", "answer": "prior a"}]
    monkeypatch.setattr(
        "app.routers.v1.investigate.get_context",
        AsyncMock(return_value=ConversationContext(intent=Intent.TOP_ALERTS, params={}, transcript=prior_transcript)),
    )
    mock_append_turn = AsyncMock()
    monkeypatch.setattr("app.routers.v1.investigate.append_turn", mock_append_turn)

    mock_generate = Mock(return_value="fresh answer")
    from app.clients import ollama
    monkeypatch.setattr(ollama, "generate", mock_generate)

    response = client.post(
        "/api/v1/investigate", json={"query": "top alerts", "session_id": "session-1"}, headers=headers
    )

    assert response.status_code == 200
    assert response.json()["answer"] == "fresh answer"

    prompt_sent = mock_generate.call_args.args[0]
    assert "prior q" in prompt_sent
    assert "prior a" in prompt_sent

    mock_append_turn.assert_called_once_with(str(tenant_id), "session-1", "top alerts", "fresh answer")


# ── SS-093: prompt data/instruction delimiting + output grounding ──
# Implements SS-092's (docs/ai-threat-model.md) recommended mitigation.

@pytest.mark.asyncio
async def test_generate_answer_wraps_the_tool_data_in_untrusted_data_markers(monkeypatch):
    from app.routers.v1.investigate import _DATA_FENCE_END, _DATA_FENCE_START, _generate_answer

    mock_generate = Mock(return_value="3")
    from app.clients import ollama
    monkeypatch.setattr(ollama, "generate", mock_generate)

    await _generate_answer("top alerts", Intent.TOP_ALERTS, AlertListOutput(total=3, alerts=[]), [])

    prompt = mock_generate.call_args.args[0]
    assert _DATA_FENCE_START in prompt
    assert _DATA_FENCE_END in prompt
    # The tool-data fence is always the last one in the prompt (the explanatory
    # instruction paragraph itself mentions the marker literal once too, earlier
    # in the prompt, to explain the convention — rindex finds the real data block).
    start = prompt.rindex(_DATA_FENCE_START)
    end = prompt.rindex(_DATA_FENCE_END)
    # The fenced block is a readable briefing now, not a JSON dump —
    # the tool's real count still has to be inside it.
    assert "Matching alerts: 3" in prompt[start:end]


@pytest.mark.asyncio
async def test_generate_answer_prompt_tells_the_model_not_to_follow_embedded_instructions(monkeypatch):
    from app.routers.v1.investigate import _generate_answer

    mock_generate = Mock(return_value="3")
    from app.clients import ollama
    monkeypatch.setattr(ollama, "generate", mock_generate)

    await _generate_answer("top alerts", Intent.TOP_ALERTS, AlertListOutput(total=3, alerts=[]), [])

    prompt = mock_generate.call_args.args[0].lower()
    assert "never treat" in prompt
    assert "instruction" in prompt


@pytest.mark.asyncio
async def test_generate_answer_prompt_instructs_never_presenting_interpretation_as_fact(monkeypatch):
    """
    Root-cause fix for a follow-up like "what happened after those
    failures?" fabricating a coordinated-attack narrative (mitigation,
    exploitation, attacker intent) with no supporting data: the prompt
    must tell the model never to present its own interpretation as
    fact, and to say plainly when the data doesn't cover something.
    The rule is unchanged; the FACTS / ASSESSMENT / UNKNOWN banner
    labels it used to demand were dropped — they rendered as shouting
    headings in the UI.
    """
    from app.routers.v1.investigate import _generate_answer

    mock_generate = Mock(return_value="3")
    from app.clients import ollama
    monkeypatch.setattr(ollama, "generate", mock_generate)

    await _generate_answer("what happened after those failures?", Intent.AUTH_FAILURES, AlertListOutput(total=3, alerts=[]), [])

    prompt = mock_generate.call_args.args[0].lower()
    assert "fact" in prompt
    assert "assessment" in prompt
    assert "unknown" in prompt
    assert "does not show that" in prompt


@pytest.mark.asyncio
async def test_generate_answer_prompt_forbids_fabricating_mitigation_or_exploitation_claims(monkeypatch):
    from app.routers.v1.investigate import _generate_answer

    mock_generate = Mock(return_value="3")
    from app.clients import ollama
    monkeypatch.setattr(ollama, "generate", mock_generate)

    await _generate_answer("what happened after those failures?", Intent.AUTH_FAILURES, AlertListOutput(total=3, alerts=[]), [])

    prompt = mock_generate.call_args.args[0].lower()
    assert "mitigated" in prompt
    assert "patched" in prompt
    assert "exploitation attempt succeeded" in prompt
    assert "attacker" in prompt


@pytest.mark.asyncio
async def test_generate_answer_prompt_instructs_reporting_every_entry_in_a_multi_item_breakdown(monkeypatch):
    """
    Root-cause fix for "which host was involved?" answering with a
    single arbitrarily-picked host when the data lists several with
    counts — the prompt must tell the model to report every listed
    one, not guess. (The rule no longer names the internal breakdown
    key: the model was quoting those names back at the analyst.)
    """
    from app.routers.v1.investigate import _generate_answer

    mock_generate = Mock(return_value="3")
    from app.clients import ollama
    monkeypatch.setattr(ollama, "generate", mock_generate)

    await _generate_answer("which host was involved?", Intent.AUTH_FAILURES, AlertListOutput(total=3, alerts=[]), [])

    prompt = mock_generate.call_args.args[0].lower()
    assert "do not arbitrarily pick just one" in prompt
    assert "say so rather than guessing" in prompt


@pytest.mark.asyncio
async def test_generate_answer_prompt_instructs_not_overstating_the_records_shown(monkeypatch):
    """
    Issue 4, kept but reworded: the model must answer counts with the
    stated total and must never imply the example records are the
    complete set. The old wording ("partial sample", "truncated flag")
    taught it to discuss the prompt's own sampling, which it then did
    out loud in the UI.
    """
    from app.routers.v1.investigate import _generate_answer

    mock_generate = Mock(return_value="3")
    from app.clients import ollama
    monkeypatch.setattr(ollama, "generate", mock_generate)

    await _generate_answer("show failed logins", Intent.AUTH_FAILURES, AlertListOutput(total=2013, alerts=[]), [])

    prompt = mock_generate.call_args.args[0].lower()
    assert "answer counts with the stated total" in prompt
    assert "never claim or imply that the example records listed are the complete set" in prompt
    # The real total must still reach the model.
    assert "matching alerts: 2013" in prompt


@pytest.mark.asyncio
async def test_generate_answer_wraps_the_transcript_in_untrusted_data_markers_too(monkeypatch):
    """The transcript is as much an injection surface as tool data (SS-092 §1/§4E) — a prior poisoned
    answer replayed verbatim — so it gets the same fencing treatment, not just the current tool result."""
    from app.routers.v1.investigate import _DATA_FENCE_END, _DATA_FENCE_START, _generate_answer

    mock_generate = Mock(return_value="answer")
    from app.clients import ollama
    monkeypatch.setattr(ollama, "generate", mock_generate)

    transcript = [{"query": "prior q", "answer": "prior a"}]
    await _generate_answer("current q", Intent.TOP_ALERTS, AlertListOutput(total=1, alerts=[]), transcript)

    prompt = mock_generate.call_args.args[0]
    # 3, not 2: the explanatory instruction paragraph itself mentions each marker
    # literal once (to explain the convention), plus one real fence each for the
    # transcript block and the tool-data block.
    assert prompt.count(_DATA_FENCE_START) == 3
    assert prompt.count(_DATA_FENCE_END) == 3


def test_answer_appears_grounded_when_cited_numbers_are_in_the_data():
    from app.routers.v1.investigate import _answer_appears_grounded

    result = AlertListOutput(total=3, alerts=[])
    assert _answer_appears_grounded("Found 3 failed login attempts.", result) is True


def test_answer_appears_grounded_true_when_the_answer_cites_no_numbers():
    from app.routers.v1.investigate import _answer_appears_grounded

    result = AlertListOutput(total=3, alerts=[])
    assert _answer_appears_grounded("There were several failed logins.", result) is True


def test_answer_appears_grounded_false_when_a_cited_number_is_absent_from_the_data():
    """The exit-criteria case: a constructed answer referencing a fact absent from the supplied tool data."""
    from app.routers.v1.investigate import _answer_appears_grounded

    result = AlertListOutput(total=3, alerts=[])
    assert _answer_appears_grounded("Found 999 critical incidents requiring immediate action.", result) is False


@pytest.mark.asyncio
async def test_generate_answer_logs_a_warning_when_the_answer_is_not_grounded(monkeypatch):
    import app.routers.v1.investigate as investigate_module

    monkeypatch.setattr(investigate_module.ollama, "generate", Mock(return_value="Found 999 unrelated incidents."))
    mock_logger = Mock()
    monkeypatch.setattr(investigate_module, "logger", mock_logger)

    await investigate_module._generate_answer(
        "top alerts", Intent.TOP_ALERTS, AlertListOutput(total=3, alerts=[]), []
    )

    mock_logger.warning.assert_called_once()
    kwargs = mock_logger.warning.call_args.kwargs
    assert kwargs["reason"] == "ungrounded"
    assert "not found" in kwargs["detail"].lower()


@pytest.mark.asyncio
async def test_generate_answer_does_not_log_a_warning_when_the_answer_is_grounded(monkeypatch):
    import app.routers.v1.investigate as investigate_module

    monkeypatch.setattr(investigate_module.ollama, "generate", Mock(return_value="Found 3 failed logins."))
    mock_logger = Mock()
    monkeypatch.setattr(investigate_module, "logger", mock_logger)

    await investigate_module._generate_answer(
        "top alerts", Intent.TOP_ALERTS, AlertListOutput(total=3, alerts=[]), []
    )

    mock_logger.warning.assert_not_called()


@pytest.mark.asyncio
async def test_generate_answer_replaces_an_ungrounded_answer_with_the_templated_one(monkeypatch):
    """
    An answer citing a number that isn't in the data (999 here) is not
    shown: the templated answer built from the same data is used instead,
    with fallback_reason "ungrounded" — no second LLM call.
    """
    from app.core.enums import FallbackReason
    from app.routers.v1.investigate import _generate_answer

    generate = Mock(return_value="Found 999 unrelated incidents.")
    monkeypatch.setattr("app.routers.v1.investigate.ollama.generate", generate)

    answer, reason = await _generate_answer(
        "top alerts", Intent.TOP_ALERTS,
        AlertListOutput(subject="alerts in the last 24 hours", total=3, alerts=[]), [],
    )

    assert answer == "Alerts in the last 24 hours: 3."
    assert reason == FallbackReason.UNGROUNDED
    generate.assert_called_once()


# ── Latency diagnosis: prompt-data summarization + output-token cap ──
# docs/ai-llm-latency-diagnosis.md: a real query returns up to 100 full
# alert dicts (measured ~93KB/2050 tokens) - _prompt_data summarizes
# what reaches the LLM prompt specifically. InvestigateResponse.data
# (SS-083's evidence panel) is built from the untouched tool_result and
# is unaffected by any of this.

def _make_alert(i, host="DESKTOP-042", user="john.doe", severity="high"):
    return {
        "alert_id": f"a{i}", "host_id": host, "user": user, "action": "failed_login",
        "description": "Failed SSH authentication attempt", "severity": severity,
        "source_ip": "45.33.32.100", "mitre_technique": "T1110", "timestamp": "2026-08-25T02:47:11Z",
    }


def test_prompt_counts_come_from_aggregations_not_the_sample():
    """
    The sample is 5 alerts on HOST-A/HOST-B, but the aggregation over all
    500 matches says HOST-C dominates — the prompt must show the real
    totals and must not derive counts from the sample at all.
    """
    from app.routers.v1.investigate import _prompt_data

    alerts = (
        [_make_alert(i, host="HOST-A", user="alice") for i in range(3)]
        + [_make_alert(i, host="HOST-B", user="bob") for i in range(3, 5)]
    )
    result = AlertListOutput(
        total=500, alerts=alerts, truncated=True,
        counts={"Hosts": {"HOST-C": 480, "HOST-A": 15, "HOST-B": 5}},
    )

    prompt_text = _prompt_data(result)

    assert "Matching alerts: 500 in total" in prompt_text
    assert "Hosts: HOST-C (480), HOST-A (15), HOST-B (5)" in prompt_text
    assert "HOST-A (3)" not in prompt_text and "Most affected" not in prompt_text


def test_prompt_sample_rows_carry_only_the_compact_fields():
    from app.routers.v1.investigate import _describe_alert_list

    briefing = _describe_alert_list([_make_alert(1)], total=1)

    row = briefing.splitlines()[-1]
    assert row == "1. time=2026-08-25T02:47:11Z host=DESKTOP-042 user=john.doe activity=failed_login severity=high source IP=45.33.32.100"
    assert "Failed SSH authentication attempt" not in briefing and "T1110" not in briefing


def test_describe_alert_list_caps_the_example_count():
    from app.routers.v1.investigate import _PROMPT_SAMPLE_ALERT_LIMIT, _describe_alert_list

    alerts = [_make_alert(i) for i in range(50)]

    briefing = _describe_alert_list(alerts, total=50)

    assert "Matching alerts: 50" in briefing
    example_lines = [line for line in briefing.splitlines() if line[:1].isdigit()]
    assert len(example_lines) == _PROMPT_SAMPLE_ALERT_LIMIT


def test_prompt_data_summarizes_a_large_alerts_list():
    from app.routers.v1.investigate import _prompt_data

    result = AlertListOutput(total=100, alerts=[_make_alert(i) for i in range(100)], truncated=True)

    prompt_text = _prompt_data(result)

    assert len(prompt_text) < len(result.model_dump_json()) / 4  # substantially smaller than the raw dump
    assert "Matching alerts: 100" in prompt_text


def test_prompt_data_states_the_count_for_an_empty_alerts_list():
    from app.routers.v1.investigate import _prompt_data

    result = AlertListOutput(total=0, alerts=[], truncated=False)

    assert _prompt_data(result) == "Matching alerts: 0"


def test_prompt_data_summarizes_recent_alerts_on_endpoint_snapshot():
    from app.routers.v1.investigate import _prompt_data

    result = EndpointSnapshotOutput(
        host_id="DESKTOP-042", risk_score=80, risk_level="high", recent_alert_count=40,
        counts={"Activity types": {"failed_login": 39, "login_success": 1}},
        recent_alerts=[_make_alert(i) for i in range(20)], truncated=True,
    )

    prompt_text = _prompt_data(result)

    assert "Matching alerts: 40 in total" in prompt_text
    assert "Activity types: failed_login (39), login_success (1)" in prompt_text
    assert "Risk score: 80" in prompt_text  # other fields still reach the model, as readable labels


def test_prompt_data_renders_tools_without_an_alert_list_as_labeled_text():
    from app.routers.v1.investigate import _prompt_data

    result = RiskyEndpointsOutput(endpoints=[{"host_id": "H1", "risk_score": 90}], truncated=False)

    prompt_text = _prompt_data(result)

    assert "Endpoints:" in prompt_text
    assert "H1" in prompt_text and "90" in prompt_text


# ── Answer format + no internal key names in the prompt ──────────────

def test_prompt_data_contains_no_internal_key_names():
    """
    The reported symptom: the answer quoted "count_shown": 20 and
    "truncated": false straight back at the analyst. Those keys no
    longer exist in what the model sees.
    """
    from app.routers.v1.investigate import _prompt_data

    result = AlertListOutput(total=40, alerts=[_make_alert(i) for i in range(20)], truncated=True)

    prompt_text = _prompt_data(result)

    for internal_key in ("count_shown", "truncated", "top_hosts", "top_users", "severity_breakdown",
                         "sample", "alert_id", "tenant_id", "host_id", '":'):
        assert internal_key not in prompt_text, f"{internal_key} leaked into the prompt"


def test_prompt_data_is_not_json():
    from app.routers.v1.investigate import _prompt_data

    result = AlertListOutput(total=3, alerts=[_make_alert(i) for i in range(3)], truncated=False)

    prompt_text = _prompt_data(result)

    assert not prompt_text.startswith("{")
    assert "Matching alerts: 3" in prompt_text


@pytest.mark.asyncio
async def test_generate_answer_prompt_instructs_the_short_answer_format(monkeypatch):
    from app.routers.v1.investigate import _generate_answer

    mock_generate = Mock(return_value="ok")
    from app.clients import ollama
    monkeypatch.setattr(ollama, "generate", mock_generate)

    await _generate_answer("show failed logins", Intent.AUTH_FAILURES, AlertListOutput(total=3, alerts=[]), [])

    prompt = mock_generate.call_args.args[0]
    assert "Answer the question directly in 1-3 sentences FIRST" in prompt
    assert "under about 120 words" in prompt
    assert "No headings" in prompt


@pytest.mark.asyncio
async def test_generate_answer_prompt_tells_the_model_not_to_repeat_the_evidence_table(monkeypatch):
    """The Investigate page renders the raw alerts in a table right below the answer — re-listing them in prose is duplication."""
    from app.routers.v1.investigate import _generate_answer

    mock_generate = Mock(return_value="ok")
    from app.clients import ollama
    monkeypatch.setattr(ollama, "generate", mock_generate)

    await _generate_answer("show failed logins", Intent.AUTH_FAILURES, AlertListOutput(total=3, alerts=[]), [])

    prompt = mock_generate.call_args.args[0]
    assert "Lead with the answer itself" in prompt
    assert "do not repeat" in prompt
    assert "evidence table" in prompt


@pytest.mark.asyncio
async def test_generate_answer_prompt_forbids_quoting_field_names_or_identifiers(monkeypatch):
    from app.routers.v1.investigate import _generate_answer

    mock_generate = Mock(return_value="ok")
    from app.clients import ollama
    monkeypatch.setattr(ollama, "generate", mock_generate)

    await _generate_answer("show failed logins", Intent.AUTH_FAILURES, AlertListOutput(total=3, alerts=[]), [])

    prompt = mock_generate.call_args.args[0].lower()
    assert "never mention field names, keys, identifiers" in prompt
    assert "never print a uuid or a tenant identifier" in prompt


def test_answer_appears_grounded_recognizes_summarized_aggregate_counts():
    """
    Regression: the grounding check must validate against what the
    model actually saw (_prompt_data's summary), not the full raw
    dump - an aggregate count like "23" is a real, correctly-grounded
    citation of the summary even though it never appears as a literal
    field value anywhere in the raw alert list itself.
    """
    from app.routers.v1.investigate import _answer_appears_grounded

    alerts = [_make_alert(i, user="bob") for i in range(23)]
    result = AlertListOutput(total=23, alerts=alerts, truncated=False)

    assert _answer_appears_grounded("bob had 23 failed login attempts.", result) is True


@pytest.mark.asyncio
async def test_generate_answer_prompt_is_dramatically_smaller_for_a_large_alert_list(monkeypatch):
    """End-to-end: _generate_answer's actual prompt reflects the summarization, not just the helper in isolation."""
    from app.routers.v1.investigate import _generate_answer

    mock_generate = Mock(return_value="answer")
    from app.clients import ollama
    monkeypatch.setattr(ollama, "generate", mock_generate)

    result = AlertListOutput(total=100, alerts=[_make_alert(i) for i in range(100)], truncated=True)
    await _generate_answer("top alerts", Intent.TOP_ALERTS, result, [])

    prompt = mock_generate.call_args.args[0]
    assert len(prompt) < len(result.model_dump_json()) / 4


def test_investigate_does_not_append_a_turn_for_an_unknown_intent(client, auth_headers, monkeypatch):
    _mock_resolve_query(monkeypatch, Intent.UNKNOWN)
    mock_append_turn = AsyncMock()
    monkeypatch.setattr("app.routers.v1.investigate.append_turn", mock_append_turn)

    client.post("/api/v1/investigate", json={"query": "what's the weather?"}, headers=auth_headers)

    mock_append_turn.assert_not_called()


def test_investigate_does_not_append_a_turn_when_the_tool_call_fails(client, auth_headers, monkeypatch):
    _mock_resolve_query(monkeypatch, Intent.TOP_ALERTS)
    mock_tool_call = AsyncMock(side_effect=OpenSearchException("cluster unavailable"))
    monkeypatch.setattr("app.routers.v1.investigate.TOOLS", {Intent.TOP_ALERTS: Mock(call=mock_tool_call)})
    mock_append_turn = AsyncMock()
    monkeypatch.setattr("app.routers.v1.investigate.append_turn", mock_append_turn)

    client.post("/api/v1/investigate", json={"query": "top alerts"}, headers=auth_headers)

    mock_append_turn.assert_not_called()


def test_investigate_generates_a_session_id_when_none_provided(client, auth_headers, monkeypatch):
    _mock_resolve_query(monkeypatch, Intent.UNKNOWN)

    response = client.post("/api/v1/investigate", json={"query": "anything"}, headers=auth_headers)

    session_id = response.json()["session_id"]
    assert uuid.UUID(session_id)  # a real, valid UUID — doesn't raise


def test_investigate_reuses_a_provided_session_id(client, auth_headers, monkeypatch):
    _mock_resolve_query(monkeypatch, Intent.UNKNOWN)
    my_session = "my-existing-session-id"

    response = client.post(
        "/api/v1/investigate", json={"query": "anything", "session_id": my_session}, headers=auth_headers
    )

    assert response.json()["session_id"] == my_session


def test_investigate_falls_back_to_a_templated_summary_when_the_llm_fails(client, auth_headers, monkeypatch):
    _mock_resolve_query(monkeypatch, Intent.TOP_ALERTS)
    mock_tool_call = AsyncMock(return_value=AlertListOutput(total=5, alerts=[]))
    monkeypatch.setattr("app.routers.v1.investigate.TOOLS", {Intent.TOP_ALERTS: Mock(call=mock_tool_call)})

    from app.clients import ollama
    monkeypatch.setattr(ollama, "generate", Mock(side_effect=ollama.OllamaError("connection refused")))

    response = client.post("/api/v1/investigate", json={"query": "top alerts"}, headers=auth_headers)

    assert response.status_code == 200  # the request itself must not fail
    body = response.json()
    assert "5" in body["answer"]
    assert body["is_fallback"] is True


def test_investigate_asks_for_a_missing_parameter_when_tool_validation_fails(client, auth_headers, monkeypatch):
    """
    SS-085: a classified intent whose params fail the tool's own input
    validation (e.g. IP_ACTIVITY resolved without an `ip`) must not
    500. TOOLS is left unmocked here so the real MCPTool.call() raises
    a genuine pydantic.ValidationError for the missing required field,
    before any handler/downstream query ever runs. That is not a backend
    failure, so the answer is a clarifying question, not "ran into a
    problem retrieving the underlying data".
    """
    _mock_resolve_query(monkeypatch, Intent.IP_ACTIVITY)  # params default to {} — missing required "ip"

    response = client.post("/api/v1/investigate", json={"query": "what about that ip?"}, headers=auth_headers)

    assert response.status_code == 200  # not an unhandled 500
    body = response.json()
    assert body["intent"] == "ip_activity"  # the classified intent is preserved
    assert body["data"] == {}
    assert body["is_fallback"] is False
    assert body["answer"].startswith("Which IP address?")
    assert "problem retrieving" not in body["answer"]


def test_investigate_returns_an_explanatory_response_when_the_tool_call_hits_a_downstream_failure(
    client, auth_headers, monkeypatch
):
    """SS-085: an OpenSearch/Postgres failure during the tool call must degrade gracefully, not 500."""
    _mock_resolve_query(monkeypatch, Intent.TOP_ALERTS)
    mock_tool_call = AsyncMock(side_effect=OpenSearchException("cluster unavailable"))
    monkeypatch.setattr("app.routers.v1.investigate.TOOLS", {Intent.TOP_ALERTS: Mock(call=mock_tool_call)})

    response = client.post("/api/v1/investigate", json={"query": "top alerts"}, headers=auth_headers)

    assert response.status_code == 200  # not an unhandled 500
    body = response.json()
    assert body["intent"] == "top_alerts"
    assert body["data"] == {}
    assert body["is_fallback"] is True
    assert body["answer"]


def test_investigate_does_not_swallow_an_unrelated_programming_error(client, auth_headers, monkeypatch):
    """
    SS-085's tool-call except clause must stay narrow: a genuine bug
    (e.g. a TypeError from broken handler code) is not a validation or
    downstream-service failure, and must still surface as a failure
    rather than being silently absorbed into a fallback answer.
    """
    _mock_resolve_query(monkeypatch, Intent.TOP_ALERTS)
    mock_tool_call = AsyncMock(side_effect=TypeError("unexpected keyword argument"))
    monkeypatch.setattr("app.routers.v1.investigate.TOOLS", {Intent.TOP_ALERTS: Mock(call=mock_tool_call)})

    with pytest.raises(TypeError):
        client.post("/api/v1/investigate", json={"query": "top alerts"}, headers=auth_headers)


@pytest.mark.asyncio
async def test_generate_answer_falls_back_when_the_llm_exceeds_the_timeout(monkeypatch):
    """
    The SRS's 15s target must hold even if the LLM hangs — bounded by
    INVESTIGATION_LLM_TIMEOUT_SECONDS. Tested directly against the
    async function (not through TestClient's HTTP layer): TestClient
    bridges sync test code to the async app through a portal that waits
    for the event loop to go fully idle before returning control to the
    test, including a cancelled asyncio.to_thread()'s still-running
    background thread — that's a TestClient synchronization artifact,
    not a real delay a production ASGI server (uvicorn) would impose on
    the actual HTTP response, which wait_for already bounds correctly
    (confirmed independently: awaiting wait_for(to_thread(...), timeout)
    itself returns in ~timeout seconds, not the slow call's duration).
    """
    from app.core.config import settings
    from app.mcp.tools import AlertListOutput
    from app.routers.v1.investigate import _generate_answer

    monkeypatch.setattr(settings, "INVESTIGATION_LLM_TIMEOUT_SECONDS", 0.2)

    def _slow_generate(prompt, *args, **kwargs):
        time.sleep(1.0)
        return "too slow"

    from app.clients import ollama
    monkeypatch.setattr(ollama, "generate", _slow_generate)

    started = time.monotonic()
    answer, reason = await _generate_answer("top alerts", Intent.TOP_ALERTS, AlertListOutput(total=3, alerts=[]))
    elapsed = time.monotonic() - started

    assert elapsed < 0.5  # bounded by the (shortened) timeout, not the slow call's 1.0s
    assert "3" in answer
    assert reason.value == "timeout"


@pytest.mark.asyncio
async def test_generate_answer_logs_a_specific_message_on_timeout_not_an_empty_error(monkeypatch):
    """
    Regression test: asyncio.wait_for's TimeoutError carries no message
    (str(e) == "") — before this fix, the timeout case fell through to
    the generic `except Exception` handler and logged error="", making a
    real, understood timeout indistinguishable from a truly opaque
    failure. It must now log its own specific, non-empty message.
    """
    from app.core.config import settings
    from app.mcp.tools import AlertListOutput
    import app.routers.v1.investigate as investigate_module

    monkeypatch.setattr(settings, "INVESTIGATION_LLM_TIMEOUT_SECONDS", 0.2)
    monkeypatch.setattr(investigate_module.ollama, "generate", lambda prompt, *args, **kwargs: (time.sleep(1.0), "too slow")[1])
    mock_logger = Mock()
    monkeypatch.setattr(investigate_module, "logger", mock_logger)

    await investigate_module._generate_answer("top alerts", Intent.TOP_ALERTS, AlertListOutput(total=3, alerts=[]))

    mock_logger.warning.assert_called_once()
    kwargs = mock_logger.warning.call_args.kwargs
    assert kwargs["reason"] == "timeout"
    assert kwargs["detail"] == "no answer within 0.2s"  # never an empty error string


@pytest.mark.asyncio
async def test_generate_answer_logs_the_exception_type_on_a_non_timeout_failure(monkeypatch):
    """A non-timeout failure (e.g. Ollama unreachable) must still identify itself by exception type in the log."""
    from app.mcp.tools import AlertListOutput
    import app.routers.v1.investigate as investigate_module
    from app.clients import ollama

    monkeypatch.setattr(ollama, "generate", Mock(side_effect=ollama.OllamaError("connection refused")))
    mock_logger = Mock()
    monkeypatch.setattr(investigate_module, "logger", mock_logger)

    await investigate_module._generate_answer("top alerts", Intent.TOP_ALERTS, AlertListOutput(total=3, alerts=[]))

    mock_logger.warning.assert_called_once()
    kwargs = mock_logger.warning.call_args.kwargs
    assert kwargs["reason"] == "error"
    assert kwargs["detail"] == "OllamaError: connection refused"


def test_investigate_response_time_meets_the_15_second_srs_target(client, auth_headers, monkeypatch):
    """AC: meets the SRS's 15-second response time target under normal load (measured)."""
    _mock_resolve_query(monkeypatch, Intent.RISKY_ENDPOINTS)
    mock_tool_call = AsyncMock(return_value=AlertListOutput(total=0, alerts=[]))
    monkeypatch.setattr("app.routers.v1.investigate.TOOLS", {Intent.RISKY_ENDPOINTS: Mock(call=mock_tool_call)})
    monkeypatch.setattr(
        "app.routers.v1.investigate._generate_answer", AsyncMock(return_value=("No risky endpoints found.", False))
    )

    started = time.monotonic()
    response = client.post("/api/v1/investigate", json={"query": "riskiest endpoints"}, headers=auth_headers)
    elapsed = time.monotonic() - started

    assert response.status_code == 200
    assert elapsed < 15.0


# ── SS-098: investigation-assistant activity audited ───────────────
# Wires record_event() into all three of investigate()'s return points.
# actor_user_id/target_id are asserted against exact known values
# (via _headers_for/an explicit session_id) rather than just "was
# called" — make_auth_headers's own randomly-generated user_id can't
# prove the actor came from the authenticated token specifically.

def test_investigate_audits_an_unknown_intent(client, monkeypatch):
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    headers = _headers_for(tenant_id, user_id)
    _mock_resolve_query(monkeypatch, Intent.UNKNOWN)
    mock_record = AsyncMock()
    monkeypatch.setattr("app.routers.v1.investigate.record_event", mock_record)

    client.post(
        "/api/v1/investigate", json={"query": "what's the weather?", "session_id": "session-unk"}, headers=headers
    )

    mock_record.assert_called_once_with(
        "fake-db-session",
        tenant_id,
        action="investigation.query",
        target_type="investigation_session",
        target_id="session-unk",
        actor_user_id=user_id,
        details={"query": "what's the weather?", "intent": "unknown", "outcome": "unknown"},
    )


def test_investigate_audits_a_tool_call_error(client, monkeypatch):
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    headers = _headers_for(tenant_id, user_id)
    _mock_resolve_query(monkeypatch, Intent.TOP_ALERTS)
    mock_tool_call = AsyncMock(side_effect=OpenSearchException("cluster unavailable"))
    monkeypatch.setattr("app.routers.v1.investigate.TOOLS", {Intent.TOP_ALERTS: Mock(call=mock_tool_call)})
    mock_record = AsyncMock()
    monkeypatch.setattr("app.routers.v1.investigate.record_event", mock_record)

    client.post("/api/v1/investigate", json={"query": "top alerts", "session_id": "session-err"}, headers=headers)

    mock_record.assert_called_once_with(
        "fake-db-session",
        tenant_id,
        action="investigation.query",
        target_type="investigation_session",
        target_id="session-err",
        actor_user_id=user_id,
        details={"query": "top alerts", "intent": "top_alerts", "outcome": "tool_error"},
    )


def test_investigate_audits_a_successful_fallback_answer(client, monkeypatch):
    """AC: fallback success (is_fallback=True) is recorded correctly."""
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    headers = _headers_for(tenant_id, user_id)
    _mock_resolve_query(monkeypatch, Intent.TOP_ALERTS)
    mock_tool_call = AsyncMock(return_value=AlertListOutput(total=5, alerts=[]))
    monkeypatch.setattr("app.routers.v1.investigate.TOOLS", {Intent.TOP_ALERTS: Mock(call=mock_tool_call)})
    monkeypatch.setattr(
        "app.routers.v1.investigate._generate_answer", AsyncMock(return_value=("Found 5 result(s).", True))
    )
    mock_record = AsyncMock()
    monkeypatch.setattr("app.routers.v1.investigate.record_event", mock_record)

    client.post("/api/v1/investigate", json={"query": "top alerts", "session_id": "session-fb"}, headers=headers)

    mock_record.assert_called_once_with(
        "fake-db-session",
        tenant_id,
        action="investigation.query",
        target_type="investigation_session",
        target_id="session-fb",
        actor_user_id=user_id,
        details={"query": "top alerts", "intent": "top_alerts", "is_fallback": True, "outcome": "answered"},
    )


def test_investigate_audits_a_successful_genuine_answer(client, monkeypatch):
    """AC: non-fallback success (is_fallback=False) is recorded correctly."""
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    headers = _headers_for(tenant_id, user_id)
    _mock_resolve_query(monkeypatch, Intent.TOP_ALERTS)
    mock_tool_call = AsyncMock(return_value=AlertListOutput(total=5, alerts=[]))
    monkeypatch.setattr("app.routers.v1.investigate.TOOLS", {Intent.TOP_ALERTS: Mock(call=mock_tool_call)})
    monkeypatch.setattr(
        "app.routers.v1.investigate._generate_answer", AsyncMock(return_value=("Here's what I found.", False))
    )
    mock_record = AsyncMock()
    monkeypatch.setattr("app.routers.v1.investigate.record_event", mock_record)

    client.post("/api/v1/investigate", json={"query": "top alerts", "session_id": "session-ok"}, headers=headers)

    mock_record.assert_called_once_with(
        "fake-db-session",
        tenant_id,
        action="investigation.query",
        target_type="investigation_session",
        target_id="session-ok",
        actor_user_id=user_id,
        details={"query": "top alerts", "intent": "top_alerts", "is_fallback": False, "outcome": "answered"},
    )


def test_investigate_audit_failure_does_not_break_a_successful_response(client, auth_headers, monkeypatch):
    """SS-098 (best-effort, same pattern as SS-097): a record_event() failure must never break the response."""
    _mock_resolve_query(monkeypatch, Intent.TOP_ALERTS)
    mock_tool_call = AsyncMock(return_value=AlertListOutput(total=5, alerts=[]))
    monkeypatch.setattr("app.routers.v1.investigate.TOOLS", {Intent.TOP_ALERTS: Mock(call=mock_tool_call)})
    monkeypatch.setattr(
        "app.routers.v1.investigate._generate_answer", AsyncMock(return_value=("Found 5 results.", False))
    )
    monkeypatch.setattr(
        "app.routers.v1.investigate.record_event", AsyncMock(side_effect=RuntimeError("db unavailable"))
    )

    response = client.post("/api/v1/investigate", json={"query": "top alerts"}, headers=auth_headers)

    assert response.status_code == 200
    assert response.json()["answer"] == "Found 5 results."


def test_investigate_audit_failure_does_not_break_the_unknown_intent_response(client, auth_headers, monkeypatch):
    _mock_resolve_query(monkeypatch, Intent.UNKNOWN)
    monkeypatch.setattr(
        "app.routers.v1.investigate.record_event", AsyncMock(side_effect=RuntimeError("db unavailable"))
    )

    response = client.post("/api/v1/investigate", json={"query": "anything"}, headers=auth_headers)

    assert response.status_code == 200
    assert response.json()["intent"] == "unknown"
