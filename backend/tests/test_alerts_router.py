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

from app.core.enums import UserRole
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

    response = client.post("/api/v1/alerts/a1/dismiss", headers=headers)

    assert response.status_code == 200
    assert response.json()["dismissed"] is True


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
