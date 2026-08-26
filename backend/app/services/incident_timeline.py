"""
SafeSOC — Incident Investigation Timeline
Merges an incident's linked alerts (OpenSearch, real log timestamp),
audit-log activity (SS-096/097 — transitions, assignment, linking,
etc.), and investigation notes (SS-037) into one chronological
narrative (SS-099) — replacing the flat alert_ids list as the primary
way an analyst reconstructs "what happened, in what order."
"""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.opensearch import get_alerts_by_ids
from app.schemas.incidents import TimelineEntry
from app.services.audit import list_events
from app.services.incidents import get_incident, list_notes
from app.utils.logger import get_logger

logger = get_logger(__name__)

# An incident's own audit trail is bounded by how many actions have
# ever been taken on it — a page this large is effectively "all of
# them" without adding a second, unbounded query path just for this
# endpoint.
_MAX_AUDIT_ENTRIES = 1000


def _parse_alert_timestamp(raw: object) -> Optional[datetime]:
    """Mirrors db/opensearch.py:bulk_index_logs's own timestamp parsing."""
    if not isinstance(raw, str):
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


async def get_incident_timeline(
    db: AsyncSession, tenant_id: uuid.UUID, incident_id: uuid.UUID
) -> list[TimelineEntry]:
    """
    Raises:
        IncidentNotFoundError: via get_incident — also enforces the
        incident belongs to this tenant before any data is gathered.
    """
    incident = await get_incident(db, tenant_id, incident_id)

    alerts = await get_alerts_by_ids(incident.alert_ids)
    audit_events, _ = await list_events(
        db, tenant_id, target_type="incident", target_id=str(incident.id), size=_MAX_AUDIT_ENTRIES
    )
    notes = await list_notes(db, tenant_id, incident.id)

    entries: list[TimelineEntry] = []

    for alert in alerts:
        timestamp = _parse_alert_timestamp(alert.get("timestamp"))
        if timestamp is None:
            # No usable timestamp to place this alert on the timeline —
            # degrade gracefully by omitting it (matching
            # frontend/src/lib/alertLookup.ts's existing best-effort
            # convention) rather than failing the whole timeline.
            logger.warning(
                "Skipping alert with no parseable timestamp in incident timeline",
                alert_id=alert.get("alert_id"),
                incident_id=str(incident.id),
            )
            continue
        entries.append(TimelineEntry(type="alert", timestamp=timestamp, data=alert))

    for event in audit_events:
        entries.append(
            TimelineEntry(
                type="audit",
                timestamp=event.created_at,
                data={
                    "action": event.action,
                    "actor_user_id": str(event.actor_user_id) if event.actor_user_id else None,
                    "details": event.details,
                },
            )
        )

    for note in notes:
        entries.append(
            TimelineEntry(
                type="note",
                timestamp=note.created_at,
                data={"id": str(note.id), "author_user_id": str(note.author_user_id), "body": note.body},
            )
        )

    entries.sort(key=lambda entry: entry.timestamp)
    return entries
