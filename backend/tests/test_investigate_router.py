"""
SafeSOC — Investigation Router Tests
"""

import time
import uuid
from unittest.mock import AsyncMock, Mock

import pytest

from app.core.enums import Intent
from app.db.postgresql import get_db
from app.main import app
from app.mcp.tools import AlertListOutput


def _mock_resolve_query(monkeypatch, intent, params=None):
    monkeypatch.setattr(
        "app.routers.v1.investigate.resolve_query", AsyncMock(return_value=(intent, params or {}))
    )


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


def test_investigate_calls_the_matching_tool_and_returns_its_data(client, auth_headers, monkeypatch):
    _mock_resolve_query(monkeypatch, Intent.AUTH_FAILURES, {"host_id": "DESKTOP-042"})
    mock_tool_call = AsyncMock(return_value=AlertListOutput(total=2, alerts=[{"alert_id": "a1"}, {"alert_id": "a2"}]))
    monkeypatch.setattr("app.routers.v1.investigate.TOOLS", {Intent.AUTH_FAILURES: Mock(call=mock_tool_call)})
    monkeypatch.setattr(
        "app.routers.v1.investigate._generate_answer", AsyncMock(return_value="Found 2 failed logins.")
    )

    response = client.post(
        "/api/v1/investigate", json={"query": "failed logins for DESKTOP-042"}, headers=auth_headers
    )

    assert response.status_code == 200
    body = response.json()
    assert body["intent"] == "auth_failures"
    assert body["answer"] == "Found 2 failed logins."
    assert body["data"]["total"] == 2
    mock_tool_call.assert_called_once()


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
    assert "5" in response.json()["answer"]


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

    def _slow_generate(prompt):
        time.sleep(1.0)
        return "too slow"

    from app.clients import ollama
    monkeypatch.setattr(ollama, "generate", _slow_generate)

    started = time.monotonic()
    answer = await _generate_answer("top alerts", Intent.TOP_ALERTS, AlertListOutput(total=3, alerts=[]))
    elapsed = time.monotonic() - started

    assert elapsed < 0.5  # bounded by the (shortened) timeout, not the slow call's 1.0s
    assert "3" in answer


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
    monkeypatch.setattr(investigate_module.ollama, "generate", lambda prompt: (time.sleep(1.0), "too slow")[1])
    mock_logger = Mock()
    monkeypatch.setattr(investigate_module, "logger", mock_logger)

    await investigate_module._generate_answer("top alerts", Intent.TOP_ALERTS, AlertListOutput(total=3, alerts=[]))

    mock_logger.warning.assert_called_once()
    message, kwargs = mock_logger.warning.call_args.args[0], mock_logger.warning.call_args.kwargs
    assert "timed out" in message
    assert kwargs["timeout_seconds"] == 0.2
    assert "error" not in kwargs  # not the generic path — no empty error="" string


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
    message, kwargs = mock_logger.warning.call_args.args[0], mock_logger.warning.call_args.kwargs
    assert "failed" in message
    assert kwargs["error_type"] == "OllamaError"
    assert kwargs["error"] == "connection refused"


def test_investigate_response_time_meets_the_15_second_srs_target(client, auth_headers, monkeypatch):
    """AC: meets the SRS's 15-second response time target under normal load (measured)."""
    _mock_resolve_query(monkeypatch, Intent.RISKY_ENDPOINTS)
    mock_tool_call = AsyncMock(return_value=AlertListOutput(total=0, alerts=[]))
    monkeypatch.setattr("app.routers.v1.investigate.TOOLS", {Intent.RISKY_ENDPOINTS: Mock(call=mock_tool_call)})
    monkeypatch.setattr(
        "app.routers.v1.investigate._generate_answer", AsyncMock(return_value="No risky endpoints found.")
    )

    started = time.monotonic()
    response = client.post("/api/v1/investigate", json={"query": "riskiest endpoints"}, headers=auth_headers)
    elapsed = time.monotonic() - started

    assert response.status_code == 200
    assert elapsed < 15.0
