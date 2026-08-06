"""
SafeSOC — Incident Service
Turns a detected correlation chain (SS-028) into exactly one Incident
(SS-035 model): merges into an existing active incident that already
references any of the chain's alert_ids, rather than creating a
duplicate every time the same chain re-fires as more alerts join it.
Also provides manual incident creation, listing, retrieval, and
lifecycle-transition enforcement (SS-036) for routers/v1/incidents.py.
"""

import uuid
from typing import Optional

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import IncidentStatus
from app.core.exceptions import IncidentNotFoundError, InvalidStateTransitionError
from app.models.incident import Incident, IncidentStateTransition
from app.services.correlation import DetectedChain

# Incidents in either of these statuses are still "live" and eligible to
# absorb a newly-detected chain; resolved/false-positive incidents are not
# reopened by a re-detection — a new incident is created instead.
_ACTIVE_STATUSES = (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING)

# Lifecycle state machine (SS-036): the only path is open -> investigating
# -> resolved/false_positive, exactly as documented in docs/api-design.md.
# No skipping ahead (open -> resolved) and no backward moves (e.g. the
# AC's own example, resolved -> open) — resolved/false_positive are
# terminal; reopening a closed incident is intentionally out of scope
# here and would be a new incident instead.
_ALLOWED_TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    IncidentStatus.OPEN: frozenset({IncidentStatus.INVESTIGATING}),
    IncidentStatus.INVESTIGATING: frozenset({IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE}),
    IncidentStatus.RESOLVED: frozenset(),
    IncidentStatus.FALSE_POSITIVE: frozenset(),
}


async def _create_new_incident(db: AsyncSession, tenant_id: uuid.UUID, alert_ids: list[str]) -> Incident:
    """Shared by create_or_merge_incident's "no match" path and manual creation (SS-036)."""
    incident = Incident(id=uuid.uuid4(), tenant_id=tenant_id, alert_ids=list(alert_ids), status=IncidentStatus.OPEN)
    db.add(incident)
    db.add(IncidentStateTransition(incident_id=incident.id, from_status=None, to_status=IncidentStatus.OPEN))
    await db.commit()
    await db.refresh(incident)
    return incident


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

    return await _create_new_incident(db, tenant_id, list(chain.alert_ids))


async def create_incident(db: AsyncSession, tenant_id: uuid.UUID, alert_ids: Optional[list[str]] = None) -> Incident:
    """
    Manually open an incident (SS-036), independent of correlation-chain
    auto-detection (SS-031). No advisory lock here: unlike
    create_or_merge_incident, this isn't invoked by a batch of concurrent
    Celery tasks racing on the same tenant+host — it's one direct request.
    """
    return await _create_new_incident(db, tenant_id, alert_ids or [])


async def list_incidents(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    status: Optional[IncidentStatus] = None,
    page: int = 1,
    size: int = 50,
) -> tuple[list[Incident], int]:
    """List incidents scoped to a tenant, optionally filtered by status, newest first."""
    filters = [Incident.tenant_id == tenant_id]
    if status is not None:
        filters.append(Incident.status == status)

    count_result = await db.execute(select(func.count()).select_from(Incident).where(*filters))
    total = count_result.scalar_one()

    result = await db.execute(
        select(Incident).where(*filters).order_by(Incident.created_at.desc()).offset((page - 1) * size).limit(size)
    )
    return list(result.scalars().all()), total


async def get_incident(db: AsyncSession, tenant_id: uuid.UUID, incident_id: uuid.UUID) -> Incident:
    """
    Fetch a single incident scoped to a tenant.

    Raises:
        IncidentNotFoundError: if no incident with this id exists for
        this tenant — including when it exists under a different tenant,
        so a caller can't distinguish "not found" from "not yours."
    """
    result = await db.execute(select(Incident).where(Incident.id == incident_id, Incident.tenant_id == tenant_id))
    incident = result.scalar_one_or_none()
    if incident is None:
        raise IncidentNotFoundError(incident_id)
    return incident


async def transition_incident(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
    to_status: IncidentStatus,
    changed_by_user_id: Optional[uuid.UUID] = None,
) -> Incident:
    """
    Move an incident through its lifecycle, recording the transition as
    an audit-trail row (timestamp + acting user, per SRS §3.3).

    Raises:
        IncidentNotFoundError: via get_incident.
        InvalidStateTransitionError: if to_status isn't reachable from
        the incident's current status per _ALLOWED_TRANSITIONS.
    """
    incident = await get_incident(db, tenant_id, incident_id)

    if to_status not in _ALLOWED_TRANSITIONS[incident.status]:
        raise InvalidStateTransitionError(incident.status, to_status)

    from_status = incident.status
    incident.status = to_status
    db.add(
        IncidentStateTransition(
            incident_id=incident.id,
            from_status=from_status,
            to_status=to_status,
            changed_by_user_id=changed_by_user_id,
        )
    )
    await db.commit()
    await db.refresh(incident)
    return incident
