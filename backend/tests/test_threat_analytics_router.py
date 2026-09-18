"""
SafeSOC — Threat Analytics Router Tests (SS-111)
"""

import pytest

from app.db.postgresql import get_db
from app.main import app


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _FakeSession:
    def __init__(self, rows=None):
        self.rows = list(rows or [])

    async def execute(self, stmt, params=None):
        return _FakeResult(self.rows)


@pytest.fixture
def db_session():
    fake_session = _FakeSession()

    async def override_get_db():
        yield fake_session

    app.dependency_overrides[get_db] = override_get_db
    yield fake_session
    app.dependency_overrides.pop(get_db, None)


def test_get_analytics_requires_authentication(client, db_session):
    response = client.get("/api/v1/threat-analytics")
    assert response.status_code == 401


def test_get_analytics_is_readable_by_a_viewer(client, db_session, make_auth_headers):
    from app.core.enums import UserRole

    headers = make_auth_headers(role=UserRole.VIEWER)

    response = client.get("/api/v1/threat-analytics", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["window_days"] == 7
    assert body["trends"] == []


def test_get_analytics_respects_the_window_days_query_param(client, db_session, auth_headers):
    response = client.get("/api/v1/threat-analytics?window_days=30", headers=auth_headers)

    assert response.status_code == 200
    assert response.json()["window_days"] == 30


def test_get_analytics_rejects_a_window_days_out_of_bounds(client, db_session, auth_headers):
    response = client.get("/api/v1/threat-analytics?window_days=0", headers=auth_headers)
    assert response.status_code == 422

    response = client.get("/api/v1/threat-analytics?window_days=91", headers=auth_headers)
    assert response.status_code == 422


def test_get_analytics_response_includes_the_extended_analytics_sections(client, db_session, auth_headers):
    """AC: the response carries every section the Threat Analytics page renders, not just the original trend table."""
    response = client.get("/api/v1/threat-analytics", headers=auth_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["has_previous_period_data"] is False  # empty fake session -> nothing in either window
    assert body["kpis"] == {
        "total_incidents": 0, "open_incidents": 0, "critical_high_incidents": 0,
        "incidents_with_unknown_severity": 0, "affected_endpoints": 0, "affected_users": 0,
        "detection_categories": 0,
    }
    assert len(body["daily_trend"]) == 7  # zero-filled window, not an empty list
    assert all(day["count"] == 0 for day in body["daily_trend"])
    assert len(body["status_breakdown"]) == 4  # every IncidentStatus present, even at zero
    assert all(row["count"] == 0 for row in body["status_breakdown"])
    assert len(body["severity_breakdown"]) == 4  # every Severity present, even at zero
    assert body["mitre_techniques"] == []
    assert body["affected_assets"] == []
