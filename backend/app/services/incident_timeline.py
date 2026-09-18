"""
SafeSOC — Incident Investigation Timeline
Merges an incident's linked alerts (OpenSearch, real log timestamp),
audit-log activity (SS-096/097 — transitions, assignment, linking,
etc.), SOAR playbook/action lifecycle activity (Phase 3.5), and
investigation notes (SS-037) into one chronological narrative (SS-099)
— replacing the flat alert_ids list as the primary way an analyst
reconstructs "what happened, in what order."

The SOAR events are the same audit rows the SOAR services already
wrote; they're recorded against the run/action they describe rather
than against the incident, so they're gathered by resolving this
incident's own run/action ids first (services/soar.py::
list_incident_audit_target_ids) instead of by widening the
incident-scoped query. They arrive here as ordinary type="audit"
entries — the frontend already renders those, and the `action` string
("soar.action.approved", ...) is what distinguishes them.
"""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.opensearch import get_alerts_by_ids
from app.models.audit_log import AuditLog
from app.schemas.incidents import TimelineEntry
from app.services.audit import list_events
from app.services.incidents import get_incident, list_notes
from app.services.soar import list_incident_audit_target_ids
from app.utils.logger import get_logger

logger = get_logger(__name__)

# An incident's own audit trail is bounded by how many actions have
# ever been taken on it — a page this large is effectively "all of
# them" without adding a second, unbounded query path just for this
# endpoint.
_MAX_AUDIT_ENTRIES = 1000

# The SOAR lifecycle moments worth a place in the incident's narrative.
# The audit trail itself is NOT filtered — every SOAR event ever
# recorded stays in audit_log, queryable in full; this is only about
# what earns a line in the story an analyst reads top to bottom.
#
# Two pairs of SOAR events fire within milliseconds of each other and
# describe one moment between them, so only one of each pair is listed
# here — showing both would read as the timeline stuttering:
#   soar.playbook_run.created + soar.playbook.triggered -> triggered
#   soar.action.queued        + soar.action.started     -> started
# (soar.action.succeeded/failed are listed alongside .verified/
# .verification_failed deliberately: those genuinely are two different
# facts — what the adapter reported, and whether we could confirm it.)
#
# A new SOAR audit action added later will NOT appear on the timeline
# until it's added here. That's the intended direction of failure: a
# missing line is a visible gap someone reports, whereas an unfiltered
# feed quietly buries the events that matter.
_SOAR_TIMELINE_ACTIONS = frozenset({
    "soar.playbook.triggered",
    "soar.playbook_run.cancelled",
    "soar.action.skipped",
    "soar.action.awaiting_approval",
    "soar.action.approved",
    "soar.action.rejected",
    "soar.action.started",
    "soar.action.succeeded",
    "soar.action.failed",
    "soar.action.verified",
    "soar.action.verification_failed",
})


def _parse_alert_timestamp(raw: object) -> Optional[datetime]:
    """Mirrors db/opensearch.py:bulk_index_logs's own timestamp parsing."""
    if not isinstance(raw, str):
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


async def _list_soar_events(db: AsyncSession, tenant_id: uuid.UUID, incident_id: uuid.UUID) -> list[AuditLog]:
    """
    This incident's SOAR audit events, across both target_types the
    SOAR services write to. Returns [] for an incident with no SOAR
    activity without issuing the audit queries at all.

    Best-effort, like every other secondary source this timeline pulls
    from: SOAR is an add-on to the incident's story, and a failure
    reading it must not cost the analyst the alerts, notes, and
    incident audit trail that make up the rest of the timeline.
    """
    try:
        run_ids, action_ids = await list_incident_audit_target_ids(db, incident_id)
        events = []
        if run_ids:
            run_events, _ = await list_events(
                db, tenant_id, target_type="soar_playbook_run", target_ids=run_ids, size=_MAX_AUDIT_ENTRIES
            )
            events += run_events
        if action_ids:
            action_events, _ = await list_events(
                db, tenant_id, target_type="soar_action_execution", target_ids=action_ids, size=_MAX_AUDIT_ENTRIES
            )
            events += action_events
        return [event for event in events if event.action in _SOAR_TIMELINE_ACTIONS]
    except Exception as e:
        logger.warning(
            "Failed to read SOAR events for incident timeline — returning the rest of the timeline",
            incident_id=str(incident_id), error_type=type(e).__name__, error=str(e),
        )
        return []


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
    audit_events += await _list_soar_events(db, tenant_id, incident.id)
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
