"""
SafeSOC — Incident Summary Tests
hosts/severity derivation (services/incident_summary.py) and the
incident endpoints that return them. OpenSearch is replaced by
conftest's _mock_incident_summary_lookup, configured per test.
"""

import uuid
from datetime import datetime, timezone

import pytest

from app.core.enums import IncidentStatus, Severity, UserRole
from app.models.incident import Incident
from app.services.incident_summary import summarize_incident, summarize_incidents
from tests.test_incidents_router import _seeded_incident, db_session  # noqa: F401 — db_session is a fixture


def _incident(alert_ids: list[str]) -> Incident:
    now = datetime.now(timezone.utc)
    return Incident(
        id=uuid.uuid4(), tenant_id=uuid.uuid4(), status=IncidentStatus.OPEN,
        alert_ids=alert_ids, tags=[], created_at=now, updated_at=now,
    )


def _alert(alert_id: str, host_id: str = "HOST-A", severity: str = "low", source: str = "wazuh") -> dict:
    return {"alert_id": alert_id, "host_id": host_id, "severity": severity, "source": source}


def _by_id(*alerts: dict) -> dict[str, dict]:
    return {alert["alert_id"]: alert for alert in alerts}


# ── summarize_incident ───────────────────────────────────────────

def test_hosts_are_deduplicated_and_ordered_by_alert_count():
    incident = _incident(["a1", "a2", "a3", "a4", "a5"])
    alerts = _by_id(
        _alert("a1", host_id="UBUNTU-WEB-01"),
        _alert("a2", host_id="WIN10-FIN-07"),
        _alert("a3", host_id="WIN10-FIN-07"),
        _alert("a4", host_id="WIN10-FIN-07"),
        _alert("a5", host_id="UBUNTU-WEB-01"),
    )

    assert summarize_incident(incident, alerts).hosts == ["WIN10-FIN-07", "UBUNTU-WEB-01"]


def test_hosts_with_equal_counts_are_ordered_by_name():
    incident = _incident(["a1", "a2"])
    alerts = _by_id(_alert("a1", host_id="ZETA"), _alert("a2", host_id="ALPHA"))

    assert summarize_incident(incident, alerts).hosts == ["ALPHA", "ZETA"]


def test_cloudlens_resource_ids_are_not_hosts():
    incident = _incident(["a1", "a2"])
    alerts = _by_id(
        _alert("a1", host_id="arn:aws:iam::123456789012:user/ci-bot", source="cloudlens"),
        _alert("a2", host_id="WIN10-FIN-07"),
    )

    assert summarize_incident(incident, alerts).hosts == ["WIN10-FIN-07"]


def test_severity_is_the_highest_linked_alert_severity():
    incident = _incident(["a1", "a2", "a3"])
    alerts = _by_id(_alert("a1", severity="medium"), _alert("a2", severity="critical"), _alert("a3", severity="high"))

    assert summarize_incident(incident, alerts).severity == Severity.CRITICAL


def test_an_unknown_severity_value_is_ignored_not_fatal():
    incident = _incident(["a1", "a2"])
    alerts = _by_id(_alert("a1", severity="bogus"), _alert("a2", severity="medium"))

    assert summarize_incident(incident, alerts).severity == Severity.MEDIUM


def test_severity_is_null_and_hosts_empty_when_no_alerts_resolve():
    summary = summarize_incident(_incident(["gone-1", "gone-2"]), {})

    assert summary.severity is None
    assert summary.hosts == []


# ── summarize_incidents (batching) ───────────────────────────────

@pytest.mark.asyncio
async def test_summarize_incidents_makes_one_lookup_for_every_incident(_mock_incident_summary_lookup):
    first, second = _incident(["a1", "a2"]), _incident(["a2", "a3"])
    _mock_incident_summary_lookup.return_value = [
        _alert("a1", host_id="H1", severity="low"),
        _alert("a2", host_id="H2", severity="high"),
        _alert("a3", host_id="H3", severity="medium"),
    ]

    summaries = await summarize_incidents([first, second])

    _mock_incident_summary_lookup.assert_awaited_once_with(["a1", "a2", "a3"])
    assert summaries[first.id].severity == Severity.HIGH
    assert summaries[second.id].hosts == ["H2", "H3"]


@pytest.mark.asyncio
async def test_an_opensearch_failure_leaves_incidents_unsummarized(_mock_incident_summary_lookup):
    incident = _incident(["a1"])
    _mock_incident_summary_lookup.side_effect = ConnectionError("opensearch down")

    summaries = await summarize_incidents([incident])

    assert summaries[incident.id].hosts == []
    assert summaries[incident.id].severity is None


# ── Endpoints ────────────────────────────────────────────────────

@pytest.mark.parametrize("page_size", [1, 5, 25])
def test_list_endpoint_calls_get_alerts_by_ids_once_regardless_of_page_size(
    page_size, client, db_session, make_auth_headers, _mock_incident_summary_lookup  # noqa: F811
):
    tenant_id = uuid.uuid4()
    db_session.existing_incidents = [
        _seeded_incident(tenant_id=tenant_id, alert_ids=[f"a{i}"]) for i in range(page_size)
    ]
    headers = make_auth_headers(tenant_id=tenant_id, role=UserRole.VIEWER)

    response = client.get("/api/v1/incidents", params={"size": page_size}, headers=headers)

    assert response.status_code == 200
    assert len(response.json()["incidents"]) == page_size
    assert _mock_incident_summary_lookup.await_count == 1


def test_list_endpoint_returns_hosts_and_severity(
    client, db_session, make_auth_headers, _mock_incident_summary_lookup  # noqa: F811
):
    tenant_id = uuid.uuid4()
    db_session.existing_incidents = [_seeded_incident(tenant_id=tenant_id, alert_ids=["a1", "a2", "a3"])]
    _mock_incident_summary_lookup.return_value = [
        _alert("a1", host_id="WIN10-FIN-07", severity="medium"),
        _alert("a2", host_id="WIN10-FIN-07", severity="high"),
        _alert("a3", host_id="arn:aws:s3:::finance-exports", severity="low", source="cloudlens"),
    ]
    headers = make_auth_headers(tenant_id=tenant_id, role=UserRole.VIEWER)

    incident = client.get("/api/v1/incidents", headers=headers).json()["incidents"][0]

    assert incident["hosts"] == ["WIN10-FIN-07"]
    assert incident["severity"] == "high"


def test_detail_endpoint_returns_hosts_and_severity(
    client, db_session, make_auth_headers, _mock_incident_summary_lookup  # noqa: F811
):
    tenant_id = uuid.uuid4()
    incident = _seeded_incident(tenant_id=tenant_id, alert_ids=["a1"])
    db_session.existing_incidents = [incident]
    _mock_incident_summary_lookup.return_value = [_alert("a1", host_id="UBUNTU-WEB-01", severity="critical")]
    headers = make_auth_headers(tenant_id=tenant_id, role=UserRole.VIEWER)

    body = client.get(f"/api/v1/incidents/{incident.id}", headers=headers).json()

    assert body["hosts"] == ["UBUNTU-WEB-01"]
    assert body["severity"] == "critical"


def test_detail_endpoint_severity_is_null_when_no_alerts_resolve(
    client, db_session, make_auth_headers  # noqa: F811
):
    tenant_id = uuid.uuid4()
    incident = _seeded_incident(tenant_id=tenant_id, alert_ids=["pruned"])
    db_session.existing_incidents = [incident]
    headers = make_auth_headers(tenant_id=tenant_id, role=UserRole.VIEWER)

    body = client.get(f"/api/v1/incidents/{incident.id}", headers=headers).json()

    assert body["hosts"] == []
    assert body["severity"] is None
