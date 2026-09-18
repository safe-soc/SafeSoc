"""
SafeSOC — Shared Audit Log Service
record_event()/list_events() for the shared, tenant-scoped audit trail
(SS-096, pulling SS-071 forward — see docs/decisions.md ADR-010).

Deliberately minimal: this issue establishes the persistence layer
only. Wiring individual actions (incident transitions, alert linking,
assignment, classification, investigation-assistant activity) into it
is future work (SS-097/098), not done here — nothing calls
record_event() yet.
"""

import uuid
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog


async def record_event(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    action: str,
    target_type: str,
    target_id: str,
    actor_user_id: Optional[uuid.UUID] = None,
    details: Optional[dict] = None,
) -> AuditLog:
    """
    Record one audit-log entry. Self-commits, matching every other
    service function in this codebase (e.g. services/incidents.py's
    add_note/transition_incident) rather than expecting the caller to
    manage the transaction.
    """
    entry = AuditLog(
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        details=details or {},
    )
    db.add(entry)
    await db.commit()
    await db.refresh(entry)
    return entry


async def list_events(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
    target_ids: Optional[list[str]] = None,
    page: int = 1,
    size: int = 50,
) -> tuple[list[AuditLog], int]:
    """
    List a tenant's audit events, optionally scoped to one target
    entity, newest first — mirrors services/incidents.py:list_incidents's
    pagination pattern exactly.

    `target_ids` scopes to SEVERAL targets of the same target_type in
    one query, for callers holding a set of related ids rather than a
    single one (services/incident_timeline.py, gathering the SOAR runs
    and action executions belonging to one incident). An empty list
    matches nothing, which is the honest reading of "scope this to
    these targets" when there are none — never silently widened to
    "every target in the tenant". Combining it with `target_id` narrows
    to the intersection; callers pass one or the other.
    """
    filters = [AuditLog.tenant_id == tenant_id]
    if target_type is not None:
        filters.append(AuditLog.target_type == target_type)
    if target_id is not None:
        filters.append(AuditLog.target_id == target_id)
    if target_ids is not None:
        filters.append(AuditLog.target_id.in_(target_ids))

    count_result = await db.execute(select(func.count()).select_from(AuditLog).where(*filters))
    total = count_result.scalar_one()

    result = await db.execute(
        select(AuditLog).where(*filters).order_by(AuditLog.created_at.desc()).offset((page - 1) * size).limit(size)
    )
    return list(result.scalars().all()), total
