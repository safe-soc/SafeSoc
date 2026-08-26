"""
SafeSOC — Investigation Graph Data
Produces a lightweight Defender-style relationship view of an
incident's already-detected activity (SS-104) — explicitly no graph
database: nodes are the entities SS-100's extraction already
identifies, edges are the alerts connecting them, computed fresh from
Postgres/OpenSearch on every request with no new persistence.

Nodes reuse get_incident_evidence()'s output directly so this graph
can never show an entity the Evidence Explorer (SS-101) doesn't also
show. Edges connect every pair of entities that co-occur on the same
alert (e.g. a host and the user who triggered it, or a source/
destination IP pair), annotated with that alert's MITRE technique/
tactic where the adapter populated one, and ordered by the alert's
real log timestamp.
"""

import itertools
import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import LogSource
from app.db.opensearch import get_alerts_by_ids
from app.services.incident_evidence import get_incident_evidence
from app.services.incidents import get_incident


class GraphNode(BaseModel):
    id: str
    type: str  # "host" | "ip" | "user" | "cloud_resource"
    label: str


class GraphEdge(BaseModel):
    source: str
    target: str
    alert_id: str
    timestamp: datetime
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None


class IncidentGraph(BaseModel):
    incident_id: uuid.UUID
    nodes: list[GraphNode]
    edges: list[GraphEdge]


def _parse_alert_timestamp(raw: object) -> Optional[datetime]:
    """Mirrors db/opensearch.py:bulk_index_logs' / services/incident_timeline.py's own timestamp parsing."""
    if not isinstance(raw, str):
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def _entity_node_ids_for_alert(alert: dict) -> list[str]:
    """The node ids one alert document touches, same field mapping incident_evidence.py uses for extraction."""
    ids: list[str] = []
    host_id = alert.get("host_id")
    if host_id:
        if alert.get("source") == LogSource.CLOUDLENS.value:
            ids.append(f"cloud_resource:{host_id}")
        else:
            ids.append(f"host:{host_id}")

    for field in ("source_ip", "destination_ip"):
        ip = alert.get(field)
        if ip:
            node_id = f"ip:{ip}"
            if node_id not in ids:
                ids.append(node_id)

    user = alert.get("user")
    if user and user != "unknown":
        ids.append(f"user:{user}")

    return ids


async def get_incident_graph(db: AsyncSession, tenant_id: uuid.UUID, incident_id: uuid.UUID) -> IncidentGraph:
    """
    Raises:
        IncidentNotFoundError: via get_incident — also enforces the
        incident belongs to this tenant before any data is gathered.
    """
    incident = await get_incident(db, tenant_id, incident_id)
    evidence = await get_incident_evidence(db, tenant_id, incident_id)
    alerts = await get_alerts_by_ids(incident.alert_ids)

    nodes = (
        [GraphNode(id=f"host:{h.host_id}", type="host", label=h.host_id) for h in evidence.hosts]
        + [GraphNode(id=f"ip:{ip.ip}", type="ip", label=ip.ip) for ip in evidence.ips]
        + [GraphNode(id=f"user:{u.user}", type="user", label=u.user) for u in evidence.users]
        + [
            GraphNode(id=f"cloud_resource:{c.resource_id}", type="cloud_resource", label=c.resource_id)
            for c in evidence.cloud_resources
        ]
    )

    edges: list[GraphEdge] = []
    for alert in alerts:
        alert_id = alert.get("alert_id")
        timestamp = _parse_alert_timestamp(alert.get("timestamp"))
        if not alert_id or timestamp is None:
            # Same graceful-degradation reasoning as the timeline
            # (SS-099): an alert with no usable id/timestamp can't be
            # placed on the graph, so it's omitted rather than failing
            # the whole request.
            continue

        entity_ids = _entity_node_ids_for_alert(alert)
        for source, target in itertools.combinations(entity_ids, 2):
            edges.append(
                GraphEdge(
                    source=source,
                    target=target,
                    alert_id=alert_id,
                    timestamp=timestamp,
                    mitre_technique=alert.get("mitre_technique"),
                    mitre_tactic=alert.get("mitre_tactic"),
                )
            )

    edges.sort(key=lambda edge: edge.timestamp)
    return IncidentGraph(incident_id=incident.id, nodes=nodes, edges=edges)
