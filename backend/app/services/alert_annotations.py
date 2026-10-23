"""
SafeSOC — Alert Triage Service
Acknowledge/dismiss/restore actions on an alert (SS-107): upserts a tenant-
scoped AlertAnnotation row rather than mutating the OpenSearch alert
document, and audit-logs the change through the shared log (SS-096),
matching services/incidents.py's established best-effort pattern
(SS-097) — a record_event() failure is caught and logged, never
allowed to break the triage action it describes.

A dismissal records why (DismissReason, plus an optional note, required
for "other"); restore undoes it. Both land in the audit details.
"""

import uuid
from typing import Optional

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import DismissReason, TriageStatus
from app.models.alert_annotation import AlertAnnotation
from app.services.audit import record_event
from app.utils.logger import get_logger

logger = get_logger(__name__)


async def _record_audit_event(
    db: AsyncSession, tenant_id: uuid.UUID, action: str, alert_id: str, actor_user_id: uuid.UUID,
    details: Optional[dict] = None,
) -> None:
    try:
        await record_event(
            db, tenant_id, action=action, target_type="alert", target_id=alert_id, actor_user_id=actor_user_id,
            details=details,
        )
    except Exception as e:
        logger.warning(
            "Audit logging failed for alert triage action",
            action=action,
            alert_id=alert_id,
            error_type=type(e).__name__,
            error=str(e),
        )


async def _get_or_create_annotation(
    db: AsyncSession, tenant_id: uuid.UUID, alert_id: str, actor_user_id: uuid.UUID
) -> AlertAnnotation:
    result = await db.execute(
        select(AlertAnnotation).where(AlertAnnotation.tenant_id == tenant_id, AlertAnnotation.alert_id == alert_id)
    )
    annotation = result.scalar_one_or_none()
    if annotation is None:
        # acknowledged/dismissed are explicitly set here rather than
        # relying on the column's default=False — that default only
        # applies at real INSERT time, not at Python object
        # construction, matching how models/incident.py always
        # explicitly sets Incident.status too.
        annotation = AlertAnnotation(
            tenant_id=tenant_id, alert_id=alert_id, acknowledged=False, dismissed=False,
            updated_by_user_id=actor_user_id,
        )
        db.add(annotation)
    return annotation


async def acknowledge_alert(
    db: AsyncSession, tenant_id: uuid.UUID, alert_id: str, actor_user_id: uuid.UUID
) -> AlertAnnotation:
    annotation = await _get_or_create_annotation(db, tenant_id, alert_id, actor_user_id)
    annotation.acknowledged = True
    annotation.updated_by_user_id = actor_user_id
    await db.commit()
    await db.refresh(annotation)
    await _record_audit_event(db, tenant_id, "alert.acknowledged", alert_id, actor_user_id)
    return annotation


async def dismiss_alert(
    db: AsyncSession, tenant_id: uuid.UUID, alert_id: str, actor_user_id: uuid.UUID,
    reason: DismissReason, note: Optional[str] = None,
) -> AlertAnnotation:
    annotation = await _get_or_create_annotation(db, tenant_id, alert_id, actor_user_id)
    annotation.dismissed = True
    annotation.dismiss_reason = reason
    annotation.dismiss_note = note
    annotation.updated_by_user_id = actor_user_id
    await db.commit()
    await db.refresh(annotation)
    await _record_audit_event(
        db, tenant_id, "alert.dismissed", alert_id, actor_user_id, details={"reason": reason.value, "note": note}
    )
    return annotation


async def restore_alert(
    db: AsyncSession, tenant_id: uuid.UUID, alert_id: str, actor_user_id: uuid.UUID
) -> AlertAnnotation:
    """Undo a dismissal: clears dismissed, reason and note. The audit entry keeps what was cleared."""
    annotation = await _get_or_create_annotation(db, tenant_id, alert_id, actor_user_id)
    previous_reason = annotation.dismiss_reason
    previous_note = annotation.dismiss_note
    annotation.dismissed = False
    annotation.dismiss_reason = None
    annotation.dismiss_note = None
    annotation.updated_by_user_id = actor_user_id
    await db.commit()
    await db.refresh(annotation)
    await _record_audit_event(
        db, tenant_id, "alert.restored", alert_id, actor_user_id,
        details={"previous_reason": previous_reason.value if previous_reason else None, "previous_note": previous_note},
    )
    return annotation


async def get_alert_ids_for_triage_status(
    db: AsyncSession, tenant_id: uuid.UUID, triage: TriageStatus
) -> tuple[Optional[list[str]], Optional[list[str]]]:
    """
    Translate the Alerts-page triage filter into OpenSearch alert_id
    filters: (include_ids, exclude_ids), one of them None. Triage state
    lives in Postgres and alerts in OpenSearch, so the filter is applied
    by id. Untriaged has no row to look up, so it EXCLUDES every alert
    that was acknowledged or dismissed; the other two INCLUDE only theirs.
    """
    conditions = [AlertAnnotation.tenant_id == tenant_id]
    if triage == TriageStatus.UNTRIAGED:
        conditions.append(or_(AlertAnnotation.acknowledged.is_(True), AlertAnnotation.dismissed.is_(True)))
    elif triage == TriageStatus.ACKNOWLEDGED:
        conditions += [AlertAnnotation.acknowledged.is_(True), AlertAnnotation.dismissed.is_(False)]
    else:
        conditions.append(AlertAnnotation.dismissed.is_(True))

    result = await db.execute(select(AlertAnnotation.alert_id).where(*conditions))
    alert_ids = list(result.scalars().all())
    if triage == TriageStatus.UNTRIAGED:
        return None, alert_ids
    return alert_ids, None


async def get_annotations_for_alert_ids(
    db: AsyncSession, tenant_id: uuid.UUID, alert_ids: list[str]
) -> dict[str, AlertAnnotation]:
    """Batch lookup so GET /api/v1/alerts can merge triage state into a page of results in one query."""
    if not alert_ids:
        return {}
    result = await db.execute(
        select(AlertAnnotation).where(
            AlertAnnotation.tenant_id == tenant_id, AlertAnnotation.alert_id.in_(alert_ids)
        )
    )
    return {annotation.alert_id: annotation for annotation in result.scalars().all()}
