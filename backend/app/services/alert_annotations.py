"""
SafeSOC — Alert Triage Service
Acknowledge/dismiss actions on an alert (SS-107): upserts a tenant-
scoped AlertAnnotation row rather than mutating the OpenSearch alert
document, and audit-logs the change through the shared log (SS-096),
matching services/incidents.py's established best-effort pattern
(SS-097) — a record_event() failure is caught and logged, never
allowed to break the triage action it describes.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert_annotation import AlertAnnotation
from app.services.audit import record_event
from app.utils.logger import get_logger

logger = get_logger(__name__)


async def _record_audit_event(
    db: AsyncSession, tenant_id: uuid.UUID, action: str, alert_id: str, actor_user_id: uuid.UUID
) -> None:
    try:
        await record_event(
            db, tenant_id, action=action, target_type="alert", target_id=alert_id, actor_user_id=actor_user_id
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
    db: AsyncSession, tenant_id: uuid.UUID, alert_id: str, actor_user_id: uuid.UUID
) -> AlertAnnotation:
    annotation = await _get_or_create_annotation(db, tenant_id, alert_id, actor_user_id)
    annotation.dismissed = True
    annotation.updated_by_user_id = actor_user_id
    await db.commit()
    await db.refresh(annotation)
    await _record_audit_event(db, tenant_id, "alert.dismissed", alert_id, actor_user_id)
    return annotation


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
