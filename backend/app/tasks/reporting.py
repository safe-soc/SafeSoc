"""
SafeSOC — Scheduled Weekly Report Task
Periodic Celery beat task (SS-053) that generates one PDF security
report (SS-052) per known tenant, firing on the schedule configured by
settings.REPORT_SCHEDULE_DAY/REPORT_SCHEDULE_HOUR (see
tasks/celery_app.py's beat_schedule). Each tenant is processed
independently within a single run — no tenant is skipped or doubled,
and one tenant's failure doesn't block the rest.
"""

import asyncio

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.postgresql import worker_session_factory
from app.models.tenant import Tenant
from app.services.reporting import generate_report
from app.tasks.celery_app import celery_app
from app.utils.logger import get_logger

logger = get_logger(__name__)


async def _list_tenants(db: AsyncSession) -> list[Tenant]:
    result = await db.execute(select(Tenant))
    return list(result.scalars().all())


@celery_app.task(name="app.tasks.reporting.generate_all_tenant_reports")
def generate_all_tenant_reports() -> None:
    """Celery beat entrypoint: generate one weekly report per known tenant."""
    asyncio.run(_generate_all_tenant_reports_async())


async def _generate_all_tenant_reports_async() -> None:
    # worker_session_factory (NullPool), like every other Celery task —
    # see db/postgresql.py. Nothing is left pooled for a later task's
    # event loop to inherit, so the dispose-before-and-after handling
    # this used to need is gone.
    async with worker_session_factory() as db:
        tenants = await _list_tenants(db)

        generated = 0
        for tenant in tenants:
            try:
                await generate_report(db, tenant.id)
                generated += 1
            except Exception as e:
                logger.error(
                    "Failed to generate scheduled report for tenant",
                    tenant_id=str(tenant.id), error=str(e),
                )

    logger.info("Generated scheduled tenant reports", tenant_count=len(tenants), generated=generated)
