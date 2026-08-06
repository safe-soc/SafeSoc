"""
SafeSOC — Incident Creation Service
Turns a detected correlation chain (SS-028) into exactly one Incident
(SS-035 model): merges into an existing active incident that already
references any of the chain's alert_ids, rather than creating a
duplicate every time the same chain re-fires as more alerts join it.
"""

import uuid

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import IncidentStatus
from app.models.incident import Incident, IncidentStateTransition
from app.services.correlation import DetectedChain

# Incidents in either of these statuses are still "live" and eligible to
# absorb a newly-detected chain; resolved/false-positive incidents are not
# reopened by a re-detection — a new incident is created instead.
_ACTIVE_STATUSES = (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING)


async def create_or_merge_incident(
    db: AsyncSession, tenant_id: uuid.UUID, host_id: str, chain: DetectedChain
) -> Incident:
    """
    Ensure a detected chain results in exactly one incident.

    If an active incident for this tenant already references at least
    one of the chain's alert_ids, the chain is treated as a
    re-detection of that same evolving attack: the incident's
    alert_ids are merged (union), and no new incident or transition is
    recorded. Otherwise, a new incident is created with status OPEN,
    and its creation is itself recorded as the first audit-trail
    transition (from_status=None -> to_status=OPEN), per SRS §3.3.

    A batch of alerts for the same host is queued as one Celery task
    per alert, so multiple tasks can run this check-then-create logic
    concurrently for the same tenant+host. A transaction-scoped Postgres
    advisory lock keyed on (tenant_id, host_id) serializes them, so two
    concurrent callers can't both see "no active incident yet" and both
    create one — observed live as duplicate incidents before this lock
    was added. The lock is released automatically when this function's
    single commit ends the transaction.
    """
    await db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:lock_key))"), {"lock_key": f"{tenant_id}:{host_id}"})

    result = await db.execute(
        select(Incident).where(Incident.tenant_id == tenant_id, Incident.status.in_(_ACTIVE_STATUSES))
    )
    active_incidents = result.scalars().all()

    chain_alert_ids = set(chain.alert_ids)
    matching_incident = next(
        (incident for incident in active_incidents if chain_alert_ids & set(incident.alert_ids)),
        None,
    )

    if matching_incident is not None:
        matching_incident.alert_ids = list(dict.fromkeys(matching_incident.alert_ids + list(chain.alert_ids)))
        await db.commit()
        await db.refresh(matching_incident)
        return matching_incident

    incident = Incident(id=uuid.uuid4(), tenant_id=tenant_id, alert_ids=list(chain.alert_ids), status=IncidentStatus.OPEN)
    db.add(incident)
    db.add(IncidentStateTransition(incident_id=incident.id, from_status=None, to_status=IncidentStatus.OPEN))
    await db.commit()
    await db.refresh(incident)

    return incident
