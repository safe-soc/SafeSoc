"""
SafeSOC — Demo Mode Tests (SS-065)
Network/DB-touching functions are tested with mocks/fakes; the
end-to-end "one command" flow is verified live against a real running
stack (see the batch report) since it genuinely spans Postgres, the
API, and the correlation worker together.
"""

import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from injector import demo  # noqa: E402

from app.models.tenant import Tenant  # noqa: E402


# ── _ensure_demo_tenant ──────────────────────────────────────────

class _FakeResult:
    def __init__(self, row):
        self._row = row

    def scalar_one_or_none(self):
        return self._row


class _FakeSession:
    def __init__(self, existing_tenant=None):
        self._existing_tenant = existing_tenant
        self.added = []
        self.committed = False

    async def execute(self, stmt):
        return _FakeResult(self._existing_tenant)

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        self.committed = True

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


@pytest.mark.asyncio
async def test_ensure_demo_tenant_creates_it_when_missing(monkeypatch):
    session = _FakeSession(existing_tenant=None)
    monkeypatch.setattr(demo, "async_session_factory", lambda: session)

    await demo._ensure_demo_tenant()

    assert session.committed is True
    assert len(session.added) == 1
    assert session.added[0].id == demo.DEMO_TENANT_ID


@pytest.mark.asyncio
async def test_ensure_demo_tenant_is_idempotent_when_it_already_exists(monkeypatch):
    existing = Tenant(id=demo.DEMO_TENANT_ID, name=demo.DEMO_TENANT_NAME)
    session = _FakeSession(existing_tenant=existing)
    monkeypatch.setattr(demo, "async_session_factory", lambda: session)

    await demo._ensure_demo_tenant()

    assert session.committed is False
    assert session.added == []


# ── HTTP helpers (register/login/incidents) ─────────────────────

def test_register_demo_user_treats_409_as_success(monkeypatch):
    response = Mock(status_code=409)
    monkeypatch.setattr(demo.requests, "post", Mock(return_value=response))

    demo._register_demo_user("http://api.test")  # must not raise


def test_register_demo_user_raises_on_a_real_failure(monkeypatch):
    response = Mock(status_code=500)
    response.raise_for_status.side_effect = demo.requests.exceptions.HTTPError("500")
    monkeypatch.setattr(demo.requests, "post", Mock(return_value=response))

    with pytest.raises(demo.requests.exceptions.HTTPError):
        demo._register_demo_user("http://api.test")


def test_login_returns_the_access_token(monkeypatch):
    response = Mock(status_code=200)
    response.json.return_value = {"access_token": "fake-token", "token_type": "bearer"}
    response.raise_for_status = Mock()
    monkeypatch.setattr(demo.requests, "post", Mock(return_value=response))

    token = demo._login("http://api.test")

    assert token == "fake-token"


def test_list_incidents_returns_the_raw_incident_dicts(monkeypatch):
    response = Mock(status_code=200)
    response.json.return_value = {"incidents": [{"id": "a1", "alert_ids": ["x"]}, {"id": "a2", "alert_ids": ["y"]}]}
    response.raise_for_status = Mock()
    monkeypatch.setattr(demo.requests, "get", Mock(return_value=response))

    incidents = demo._list_incidents("http://api.test", "token")

    assert incidents == [{"id": "a1", "alert_ids": ["x"]}, {"id": "a2", "alert_ids": ["y"]}]


def test_wait_for_incident_with_alert_returns_the_id_of_a_freshly_created_incident(monkeypatch):
    """The common case: none of the just-sent alert_ids belonged to any prior incident, so a new one was created."""
    response = Mock(status_code=200)
    response.json.return_value = {
        "incidents": [{"id": "unrelated", "alert_ids": ["z"]}, {"id": "brand-new", "alert_ids": ["a1", "a2"]}]
    }
    response.raise_for_status = Mock()
    monkeypatch.setattr(demo.requests, "get", Mock(return_value=response))

    result = demo._wait_for_incident_with_alert("http://api.test", "token", ["a1"], timeout_seconds=5)

    assert result == "brand-new"


def test_wait_for_incident_with_alert_finds_a_merge_into_an_already_open_incident(monkeypatch):
    """
    BUG-002 regression: a chain re-detected on a still-open incident
    (e.g. demo.py's own IN_PROGRESS_HOST, left open by design) merges
    into that *existing* incident rather than creating a new one — this
    must still count as success, not a timeout, since the incident's
    alert_ids now contain what was just sent.
    """
    response = Mock(status_code=200)
    response.json.return_value = {"incidents": [{"id": "already-open-incident", "alert_ids": ["old-1", "a1"]}]}
    response.raise_for_status = Mock()
    monkeypatch.setattr(demo.requests, "get", Mock(return_value=response))

    result = demo._wait_for_incident_with_alert("http://api.test", "token", ["a1"], timeout_seconds=5)

    assert result == "already-open-incident"


def test_wait_for_incident_with_alert_times_out_and_returns_none(monkeypatch):
    response = Mock(status_code=200)
    response.json.return_value = {"incidents": [{"id": "unrelated", "alert_ids": ["z"]}]}
    response.raise_for_status = Mock()
    monkeypatch.setattr(demo.requests, "get", Mock(return_value=response))
    monkeypatch.setattr(demo.time, "sleep", Mock())  # don't actually wait in tests

    result = demo._wait_for_incident_with_alert("http://api.test", "token", ["a1"], timeout_seconds=0.01)

    assert result is None


def test_transition_posts_the_target_status(monkeypatch):
    response = Mock(status_code=200)
    response.raise_for_status = Mock()
    mock_post = Mock(return_value=response)
    monkeypatch.setattr(demo.requests, "post", mock_post)

    demo._transition("http://api.test", "token", "incident-123", "resolved")

    mock_post.assert_called_once()
    url, kwargs = mock_post.call_args.args[0], mock_post.call_args.kwargs
    assert url == "http://api.test/api/v1/incidents/incident-123/transitions"
    assert kwargs["json"] == {"to_status": "resolved"}
    assert kwargs["headers"] == {"Authorization": "Bearer token"}


# ── _send_history ─────────────────────────────────────────────────

def test_send_history_generates_the_configured_event_count_within_the_window(monkeypatch):
    captured = {}

    def fake_send_logs(url, logs, token=None):
        captured["logs"] = logs
        captured["token"] = token
        return {"accepted": len(logs), "rejected": 0, "alert_ids": []}

    monkeypatch.setattr(demo, "send_logs", fake_send_logs)

    accepted = demo._send_history("http://api.test/api/v1/ingest", "my-token")

    assert accepted == demo.HISTORY_EVENT_COUNT
    assert captured["token"] == "my-token"
    assert len(captured["logs"]) == demo.HISTORY_EVENT_COUNT

    now = datetime.now(timezone.utc)
    earliest_allowed = now - timedelta(days=demo.HISTORY_DAYS, minutes=1)
    for log in captured["logs"]:
        ts = datetime.fromisoformat(log["timestamp"])
        assert earliest_allowed <= ts <= now + timedelta(minutes=1)
