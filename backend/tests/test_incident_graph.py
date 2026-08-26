"""
SafeSOC — Investigation Graph Data Service Tests (SS-104)
"""

import uuid
from unittest.mock import AsyncMock

import pytest

from app.core.enums import IncidentStatus
from app.core.exceptions import IncidentNotFoundError
from app.models.incident import Incident
from app.services.incident_graph import get_incident_graph


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)


class _FakeSession:
    """
    Stands in for get_incident_evidence's Endpoint/TICache annotation
    queries (empty results — no risk/TI data available), same fake
    pattern as tests/test_incident_evidence.py's own.
    """

    async def execute(self, stmt, params=None):
        return _FakeResult([])


def _incident(**overrides) -> Incident:
    fields = {"id": uuid.uuid4(), "tenant_id": uuid.uuid4(), "status": IncidentStatus.OPEN, "alert_ids": []}
    fields.update(overrides)
    return Incident(**fields)


def _mock_sources(monkeypatch, incident, alerts=None):
    monkeypatch.setattr("app.services.incident_graph.get_incident", AsyncMock(return_value=incident))
    monkeypatch.setattr("app.services.incident_graph.get_alerts_by_ids", AsyncMock(return_value=alerts or []))
    # get_incident_graph reuses get_incident_evidence for nodes — mock
    # its own dependencies (get_incident/get_alerts_by_ids) rather than
    # get_incident_evidence itself, so nodes are derived from the exact
    # same alert data as edges, proving they can't drift (matching the
    # issue's own stated design).
    monkeypatch.setattr("app.services.incident_evidence.get_incident", AsyncMock(return_value=incident))
    monkeypatch.setattr("app.services.incident_evidence.get_alerts_by_ids", AsyncMock(return_value=alerts or []))


@pytest.mark.asyncio
async def test_raises_not_found_for_a_missing_incident(monkeypatch):
    monkeypatch.setattr(
        "app.services.incident_graph.get_incident", AsyncMock(side_effect=IncidentNotFoundError(uuid.uuid4()))
    )

    with pytest.raises(IncidentNotFoundError):
        await get_incident_graph(_FakeSession(), uuid.uuid4(), uuid.uuid4())


@pytest.mark.asyncio
async def test_nodes_match_the_evidence_extraction(monkeypatch):
    incident = _incident(alert_ids=["a1"])
    alerts = [{"alert_id": "a1", "host_id": "H1", "user": "alice", "timestamp": "2026-08-01T10:00:00Z", "source": "wazuh"}]
    _mock_sources(monkeypatch, incident, alerts)

    graph = await get_incident_graph(_FakeSession(), incident.tenant_id, incident.id)

    node_ids = {n.id for n in graph.nodes}
    assert node_ids == {"host:H1", "user:alice"}


@pytest.mark.asyncio
async def test_edge_connects_every_entity_pair_on_the_same_alert(monkeypatch):
    incident = _incident(alert_ids=["a1"])
    alerts = [
        {
            "alert_id": "a1", "host_id": "H1", "user": "alice", "source_ip": "1.1.1.1",
            "timestamp": "2026-08-01T10:00:00Z", "source": "wazuh",
        }
    ]
    _mock_sources(monkeypatch, incident, alerts)

    graph = await get_incident_graph(_FakeSession(), incident.tenant_id, incident.id)

    pairs = {frozenset((e.source, e.target)) for e in graph.edges}
    assert pairs == {
        frozenset(("host:H1", "ip:1.1.1.1")),
        frozenset(("host:H1", "user:alice")),
        frozenset(("ip:1.1.1.1", "user:alice")),
    }
    assert all(e.alert_id == "a1" for e in graph.edges)


@pytest.mark.asyncio
async def test_edges_carry_mitre_annotation_from_the_alert(monkeypatch):
    incident = _incident(alert_ids=["a1"])
    alerts = [
        {
            "alert_id": "a1", "host_id": "H1", "user": "alice", "timestamp": "2026-08-01T10:00:00Z",
            "source": "wazuh", "mitre_technique": "T1110", "mitre_tactic": "Credential Access",
        }
    ]
    _mock_sources(monkeypatch, incident, alerts)

    graph = await get_incident_graph(_FakeSession(), incident.tenant_id, incident.id)

    assert graph.edges[0].mitre_technique == "T1110"
    assert graph.edges[0].mitre_tactic == "Credential Access"


@pytest.mark.asyncio
async def test_edges_are_ordered_by_real_alert_timestamp(monkeypatch):
    incident = _incident(alert_ids=["a1", "a2"])
    alerts = [
        {"alert_id": "a2", "host_id": "H1", "user": "bob", "timestamp": "2026-08-01T12:00:00Z", "source": "wazuh"},
        {"alert_id": "a1", "host_id": "H1", "user": "alice", "timestamp": "2026-08-01T09:00:00Z", "source": "wazuh"},
    ]
    _mock_sources(monkeypatch, incident, alerts)

    graph = await get_incident_graph(_FakeSession(), incident.tenant_id, incident.id)

    timestamps = [e.timestamp for e in graph.edges]
    assert timestamps == sorted(timestamps)
    assert graph.edges[0].alert_id == "a1"


@pytest.mark.asyncio
async def test_an_alert_with_only_one_entity_produces_no_edges(monkeypatch):
    """A single entity has nothing to connect to on that alert — no self-edges."""
    incident = _incident(alert_ids=["a1"])
    alerts = [{"alert_id": "a1", "host_id": "H1", "timestamp": "2026-08-01T10:00:00Z", "source": "wazuh"}]
    _mock_sources(monkeypatch, incident, alerts)

    graph = await get_incident_graph(_FakeSession(), incident.tenant_id, incident.id)

    assert graph.edges == []
    assert len(graph.nodes) == 1


@pytest.mark.asyncio
async def test_an_alert_with_no_parseable_timestamp_produces_no_edges(monkeypatch):
    """Graceful degradation, matching SS-099's timeline: can't order what can't be timestamped."""
    incident = _incident(alert_ids=["a1"])
    alerts = [{"alert_id": "a1", "host_id": "H1", "user": "alice", "source": "wazuh"}]  # no timestamp
    _mock_sources(monkeypatch, incident, alerts)

    graph = await get_incident_graph(_FakeSession(), incident.tenant_id, incident.id)

    assert graph.edges == []
    assert len(graph.nodes) == 2  # nodes still extracted; only edge placement needs a timestamp


@pytest.mark.asyncio
async def test_empty_incident_produces_an_empty_graph(monkeypatch):
    incident = _incident()
    _mock_sources(monkeypatch, incident, [])

    graph = await get_incident_graph(_FakeSession(), incident.tenant_id, incident.id)

    assert graph.nodes == []
    assert graph.edges == []
