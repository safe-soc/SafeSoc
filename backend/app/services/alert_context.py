"""
SafeSOC — Alert Context
Everything the Alerts page's expandable details row shows for one
alert, loaded on demand: the full alert document with its triage state,
the tenant incident it belongs to (if any), and cached threat intel for
its source/destination IPs.
"""

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel
from sqlalchemy import cast, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CorrelationPattern, IncidentStatus
from app.core.exceptions import AlertNotFoundError
from app.db.opensearch import get_alert_by_id
from app.models.incident import Incident
from app.services.alert_annotations import get_annotations_for_alert_ids, merge_triage_state
from app.services.incident_summary import summarize_incidents
from app.services.ip_threat_intel import IPThreatIntel, get_ip_threat_intel, is_public_ip


class AlertContextIncident(BaseModel):
    """Just what the frontend's incidentTitle() and a status badge need."""
    id: uuid.UUID
    category: Optional[CorrelationPattern] = None
    hosts: list[str]
    status: IncidentStatus
    created_at: datetime
    updated_at: datetime


class AlertIPIntel(BaseModel):
    # None = no ti_cache row for this IP at all.
    ti: Optional[IPThreatIntel] = None
    is_public: bool


class AlertContext(BaseModel):
    alert: dict
    incident: Optional[AlertContextIncident] = None
    ip_intel: dict[str, AlertIPIntel]


async def _incident_for_alert(db: AsyncSession, tenant_id: uuid.UUID, alert_id: str) -> Optional[AlertContextIncident]:
    # alert_ids is a JSON (not JSONB) column; the cast lets Postgres use
    # JSONB containment. Re-checked in Python so a loose match can never
    # attach the wrong incident.
    result = await db.execute(
        select(Incident)
        .where(Incident.tenant_id == tenant_id, cast(Incident.alert_ids, JSONB).contains([alert_id]))
        .order_by(Incident.updated_at.desc())
    )
    incident = next((i for i in result.scalars().all() if i.tenant_id == tenant_id and alert_id in (i.alert_ids or [])), None)
    if incident is None:
        return None
    summary = (await summarize_incidents([incident]))[incident.id]
    return AlertContextIncident(
        id=incident.id, category=incident.category, hosts=summary.hosts, status=incident.status,
        created_at=incident.created_at, updated_at=incident.updated_at,
    )


async def get_alert_context(db: AsyncSession, tenant_id: uuid.UUID, alert_id: str) -> AlertContext:
    """
    Raises:
        AlertNotFoundError: (404) no such alert, or it belongs to another
        tenant — get_alert_by_id itself isn't tenant-filtered, so this
        check is the tenant boundary, and it answers 404 rather than 403
        so another tenant's alert ids can't be probed.
    """
    alert = await get_alert_by_id(alert_id)
    if alert is None or str(alert.get("tenant_id")) != str(tenant_id):
        raise AlertNotFoundError(alert_id)

    annotations = await get_annotations_for_alert_ids(db, tenant_id, [alert_id])
    merge_triage_state(alert, annotations.get(alert_id))

    ips = list(dict.fromkeys(ip for ip in (alert.get("source_ip"), alert.get("destination_ip")) if ip))
    intel = await get_ip_threat_intel(db, ips)

    return AlertContext(
        alert=alert,
        incident=await _incident_for_alert(db, tenant_id, alert_id),
        ip_intel={ip: AlertIPIntel(ti=intel.get(ip), is_public=is_public_ip(ip)) for ip in ips},
    )
