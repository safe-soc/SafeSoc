"""
SafeSOC — Alerts Router Tests (SS-107)
Closes the pre-existing gap where alerts.py had no dedicated router
test file at all — covers GET /api/v1/alerts (including its SS-107
acknowledged/dismissed merge) and the new acknowledge/dismiss actions.
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from app.core.enums import DismissReason, TriageStatus, UserRole
from app.db.postgresql import get_db
from app.main import app
from app.models.alert_annotation import AlertAnnotation


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None


class _FakeSession:
    def __init__(self, existing_annotations=None):
        self.existing_annotations: list[AlertAnnotation] = list(existing_annotations or [])
        self.added: list = []

    async def execute(self, stmt, params=None):
        return _FakeResult(self.existing_annotations)

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        for obj in self.added:
            if obj.id is None:
                obj.id = uuid.uuid4()
            if obj.updated_at is None:
                obj.updated_at = datetime.now(timezone.utc)
            if obj not in self.existing_annotations:
                self.existing_annotations.append(obj)
        self.added = []

    async def refresh(self, obj):
        pass


@pytest.fixture
def db_session():
    fake_session = _FakeSession()

    async def override_get_db():
        yield fake_session

    app.dependency_overrides[get_db] = override_get_db
    yield fake_session
    app.dependency_overrides.pop(get_db, None)


@pytest.fixture(autouse=True)
def _mock_audit(monkeypatch):
    """Never attempt a real Postgres write from record_event() during these tests."""
    monkeypatch.setattr("app.services.alert_annotations.record_event", AsyncMock())


# ── GET /api/v1/alerts ───────────────────────────────────────────────

def test_get_alerts_requires_authentication(client, db_session):
    response = client.get("/api/v1/alerts")
    assert response.status_code == 401


def test_get_alerts_merges_default_annotation_state(client, db_session, make_auth_headers, monkeypatch):
    monkeypatch.setattr(
        "app.routers.v1.alerts.search_alerts",
        AsyncMock(return_value={"total": 1, "page": 1, "size": 50, "pages": 1, "alerts": [{"alert_id": "a1"}]}),
    )
    headers = make_auth_headers(role=UserRole.VIEWER)

    response = client.get("/api/v1/alerts", headers=headers)

    assert response.status_code == 200
    alert = response.json()["alerts"][0]
    assert alert["acknowledged"] is False
    assert alert["dismissed"] is False


def test_get_alerts_merges_existing_annotation_state(client, db_session, make_auth_headers, monkeypatch):
    tenant_id = uuid.uuid4()
    db_session.existing_annotations = [
        AlertAnnotation(
            id=uuid.uuid4(), tenant_id=tenant_id, alert_id="a1", acknowledged=True, dismissed=False,
            updated_by_user_id=uuid.uuid4(),
        )
    ]
    monkeypatch.setattr(
        "app.routers.v1.alerts.search_alerts",
        AsyncMock(return_value={"total": 1, "page": 1, "size": 50, "pages": 1, "alerts": [{"alert_id": "a1"}]}),
    )
    headers = make_auth_headers(tenant_id=tenant_id, role=UserRole.VIEWER)

    response = client.get("/api/v1/alerts", headers=headers)

    assert response.status_code == 200
    assert response.json()["alerts"][0]["acknowledged"] is True


# ── GET /api/v1/alerts/summary ────────────────────────────────────────

def test_get_alerts_summary_requires_authentication(client, db_session):
    response = client.get("/api/v1/alerts/summary")
    assert response.status_code == 401


def test_get_alerts_summary_returns_the_aggregation_result(client, db_session, make_auth_headers, monkeypatch):
    monkeypatch.setattr(
        "app.routers.v1.alerts.get_alert_severity_summary",
        AsyncMock(
            return_value={
                "total": 2311,
                "timerange_hours": 168,
                "by_severity": {"low": 1200, "medium": 700, "high": 350, "critical": 61},
            }
        ),
    )
    headers = make_auth_headers(role=UserRole.VIEWER)

    response = client.get("/api/v1/alerts/summary", params={"timerange_hours": 168}, headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 2311
    assert sum(body["by_severity"].values()) == body["total"]


def test_get_alerts_summary_scopes_the_query_to_the_authenticated_tenant(
    client, db_session, make_auth_headers, monkeypatch
):
    """RBAC/tenant isolation: the summary is derived from the JWT's tenant_id, never a caller-suppliable one."""
    tenant_id = uuid.uuid4()
    captured = {}

    async def fake_summary(tenant_id, timerange_hours=24, host_id=None):
        captured["tenant_id"] = tenant_id
        captured["timerange_hours"] = timerange_hours
        return {"total": 0, "timerange_hours": timerange_hours, "by_severity": {}}

    monkeypatch.setattr("app.routers.v1.alerts.get_alert_severity_summary", fake_summary)
    headers = make_auth_headers(tenant_id=tenant_id, role=UserRole.VIEWER)

    response = client.get("/api/v1/alerts/summary", headers=headers)

    assert response.status_code == 200
    assert captured["tenant_id"] == str(tenant_id)


def test_get_alerts_summary_supports_a_custom_time_window(client, db_session, make_auth_headers, monkeypatch):
    captured = {}

    async def fake_summary(tenant_id, timerange_hours=24, host_id=None):
        captured["timerange_hours"] = timerange_hours
        return {"total": 0, "timerange_hours": timerange_hours, "by_severity": {}}

    monkeypatch.setattr("app.routers.v1.alerts.get_alert_severity_summary", fake_summary)
    headers = make_auth_headers(role=UserRole.VIEWER)

    response = client.get("/api/v1/alerts/summary", params={"timerange_hours": 72}, headers=headers)

    assert response.status_code == 200
    assert captured["timerange_hours"] == 72


def test_get_alerts_summary_passes_the_host_id_query_param_through(client, db_session, make_auth_headers, monkeypatch):
    captured = {}

    async def fake_summary(tenant_id, timerange_hours=24, host_id=None):
        captured["host_id"] = host_id
        return {"total": 0, "timerange_hours": timerange_hours, "by_severity": {}}

    monkeypatch.setattr("app.routers.v1.alerts.get_alert_severity_summary", fake_summary)
    headers = make_auth_headers(role=UserRole.VIEWER)

    response = client.get("/api/v1/alerts/summary", params={"host_id": "DESKTOP-037"}, headers=headers)

    assert response.status_code == 200
    assert captured["host_id"] == "DESKTOP-037"


# ── POST /api/v1/alerts/{alert_id}/acknowledge ───────────────────────

def test_acknowledge_requires_authentication(client, db_session):
    response = client.post("/api/v1/alerts/a1/acknowledge")
    assert response.status_code == 401


def test_acknowledge_requires_analyst_role(client, db_session, make_auth_headers):
    headers = make_auth_headers(role=UserRole.VIEWER)

    response = client.post("/api/v1/alerts/a1/acknowledge", headers=headers)

    assert response.status_code == 403


def test_acknowledge_returns_200_with_acknowledged_true(client, db_session, make_auth_headers):
    headers = make_auth_headers(role=UserRole.ANALYST)

    response = client.post("/api/v1/alerts/a1/acknowledge", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["alert_id"] == "a1"
    assert body["acknowledged"] is True
    assert body["dismissed"] is False


# ── POST /api/v1/alerts/{alert_id}/dismiss ───────────────────────────

def test_dismiss_requires_analyst_role(client, db_session, make_auth_headers):
    headers = make_auth_headers(role=UserRole.VIEWER)

    response = client.post("/api/v1/alerts/a1/dismiss", headers=headers)

    assert response.status_code == 403


def test_dismiss_returns_200_with_dismissed_true(client, db_session, make_auth_headers):
    headers = make_auth_headers(role=UserRole.ANALYST)

    response = client.post("/api/v1/alerts/a1/dismiss", json={"reason": "false_positive"}, headers=headers)

    assert response.status_code == 200
    assert response.json()["dismissed"] is True
    assert response.json()["dismiss_reason"] == "false_positive"
    assert response.json()["dismiss_note"] is None


def test_acknowledge_is_reflected_on_the_next_get_alerts_call(client, db_session, make_auth_headers, monkeypatch):
    """AC: acknowledging/dismissing persists and is reflected on next page load."""
    tenant_id = uuid.uuid4()
    headers = make_auth_headers(tenant_id=tenant_id, role=UserRole.ANALYST)
    monkeypatch.setattr(
        "app.routers.v1.alerts.search_alerts",
        AsyncMock(return_value={"total": 1, "page": 1, "size": 50, "pages": 1, "alerts": [{"alert_id": "a1"}]}),
    )

    ack_response = client.post("/api/v1/alerts/a1/acknowledge", headers=headers)
    assert ack_response.status_code == 200

    get_response = client.get("/api/v1/alerts", headers=headers)
    assert get_response.json()["alerts"][0]["acknowledged"] is True


# ── Dismiss with reason / restore ────────────────────────────────────

@pytest.mark.parametrize("body", [
    None,
    {},
    {"reason": "bored"},
    {"reason": "other"},
    {"reason": "other", "note": "   "},
    {"reason": "false_positive", "note": "x" * 501},
])
def test_dismiss_rejects_a_missing_or_invalid_reason(client, db_session, make_auth_headers, body):
    headers = make_auth_headers(role=UserRole.ANALYST)

    response = client.post("/api/v1/alerts/a1/dismiss", json=body, headers=headers)

    assert response.status_code == 422
    assert db_session.existing_annotations == []


@pytest.mark.parametrize("reason", ["false_positive", "expected_activity", "duplicate"])
def test_dismiss_accepts_each_reason_without_a_note(client, db_session, make_auth_headers, reason):
    headers = make_auth_headers(role=UserRole.ANALYST)

    response = client.post("/api/v1/alerts/a1/dismiss", json={"reason": reason}, headers=headers)

    assert response.status_code == 200
    assert response.json()["dismiss_reason"] == reason


def test_dismiss_with_other_and_a_note_returns_both(client, db_session, make_auth_headers):
    headers = make_auth_headers(role=UserRole.ANALYST)

    response = client.post(
        "/api/v1/alerts/a1/dismiss", json={"reason": "other", "note": "  Red-team exercise  "}, headers=headers
    )

    assert response.status_code == 200
    assert response.json()["dismiss_reason"] == "other"
    assert response.json()["dismiss_note"] == "Red-team exercise"


def test_restore_requires_analyst_role(client, db_session, make_auth_headers):
    headers = make_auth_headers(role=UserRole.VIEWER)

    response = client.post("/api/v1/alerts/a1/restore", headers=headers)

    assert response.status_code == 403


def test_restore_clears_the_dismissal(client, db_session, make_auth_headers):
    headers = make_auth_headers(role=UserRole.ANALYST)
    client.post("/api/v1/alerts/a1/dismiss", json={"reason": "other", "note": "Test"}, headers=headers)

    response = client.post("/api/v1/alerts/a1/restore", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["dismissed"] is False
    assert body["dismiss_reason"] is None
    assert body["dismiss_note"] is None


def test_dismiss_and_restore_are_audit_logged(client, db_session, make_auth_headers, monkeypatch):
    record = AsyncMock()
    monkeypatch.setattr("app.services.alert_annotations.record_event", record)
    headers = make_auth_headers(role=UserRole.ANALYST)

    client.post("/api/v1/alerts/a1/dismiss", json={"reason": "duplicate"}, headers=headers)
    client.post("/api/v1/alerts/a1/restore", headers=headers)

    actions = [(c.kwargs["action"], c.kwargs["details"]) for c in record.call_args_list]
    assert actions == [
        ("alert.dismissed", {"reason": "duplicate", "note": None}),
        ("alert.restored", {"previous_reason": "duplicate", "previous_note": None}),
    ]


def test_get_alerts_merges_the_dismiss_reason_and_note(client, db_session, make_auth_headers, monkeypatch):
    tenant_id = uuid.uuid4()
    db_session.existing_annotations = [
        AlertAnnotation(
            id=uuid.uuid4(), tenant_id=tenant_id, alert_id="a1", acknowledged=False, dismissed=True,
            dismiss_reason=DismissReason.OTHER, dismiss_note="Pen-test", updated_by_user_id=uuid.uuid4(),
        )
    ]
    monkeypatch.setattr(
        "app.routers.v1.alerts.search_alerts",
        AsyncMock(return_value={"total": 1, "page": 1, "size": 50, "pages": 1, "alerts": [{"alert_id": "a1"}]}),
    )
    headers = make_auth_headers(tenant_id=tenant_id, role=UserRole.VIEWER)

    alert = client.get("/api/v1/alerts", headers=headers).json()["alerts"][0]

    assert alert["dismiss_reason"] == "other"
    assert alert["dismiss_note"] == "Pen-test"


# ── GET /api/v1/alerts?q=&triage= ────────────────────────────────────

_EMPTY_PAGE = {"total": 0, "page": 1, "size": 50, "pages": 0, "alerts": []}


def test_get_alerts_passes_q_through_scoped_to_the_token_tenant(client, db_session, make_auth_headers, monkeypatch):
    tenant_id = uuid.uuid4()
    search = AsyncMock(return_value=_EMPTY_PAGE)
    monkeypatch.setattr("app.routers.v1.alerts.search_alerts", search)
    headers = make_auth_headers(tenant_id=tenant_id, role=UserRole.VIEWER)

    response = client.get("/api/v1/alerts", params={"q": "WIN10", "severity": "high"}, headers=headers)

    assert response.status_code == 200
    kwargs = search.call_args.kwargs
    assert kwargs["tenant_id"] == str(tenant_id)
    assert kwargs["q"] == "WIN10"
    assert kwargs["severity"] == "high"
    assert kwargs["alert_ids_include"] is None and kwargs["alert_ids_exclude"] is None


def test_get_alerts_rejects_an_overlong_q(client, db_session, make_auth_headers, monkeypatch):
    monkeypatch.setattr("app.routers.v1.alerts.search_alerts", AsyncMock(return_value=_EMPTY_PAGE))
    headers = make_auth_headers(role=UserRole.VIEWER)

    response = client.get("/api/v1/alerts", params={"q": "a" * 201}, headers=headers)

    assert response.status_code == 422


def test_get_alerts_rejects_an_unknown_triage_value(client, db_session, make_auth_headers, monkeypatch):
    monkeypatch.setattr("app.routers.v1.alerts.search_alerts", AsyncMock(return_value=_EMPTY_PAGE))
    headers = make_auth_headers(role=UserRole.VIEWER)

    response = client.get("/api/v1/alerts", params={"triage": "maybe"}, headers=headers)

    assert response.status_code == 422


@pytest.mark.parametrize("triage, include, exclude", [
    ("dismissed", ["a1"], None),
    ("acknowledged", ["a1"], None),
    ("untriaged", None, ["a1"]),
])
def test_get_alerts_turns_the_triage_filter_into_id_filters(
    client, db_session, make_auth_headers, monkeypatch, triage, include, exclude
):
    tenant_id = uuid.uuid4()
    lookup = AsyncMock(return_value=(include, exclude))
    monkeypatch.setattr("app.routers.v1.alerts.get_alert_ids_for_triage_status", lookup)
    search = AsyncMock(return_value=_EMPTY_PAGE)
    monkeypatch.setattr("app.routers.v1.alerts.search_alerts", search)
    headers = make_auth_headers(tenant_id=tenant_id, role=UserRole.VIEWER)

    response = client.get("/api/v1/alerts", params={"triage": triage}, headers=headers)

    assert response.status_code == 200
    assert lookup.call_args.args[1] == tenant_id
    assert lookup.call_args.args[2] == TriageStatus(triage)
    assert search.call_args.kwargs["alert_ids_include"] == include
    assert search.call_args.kwargs["alert_ids_exclude"] == exclude
