"""
SafeSOC — Endpoint Software Inventory Service
Demonstration-level software/vulnerability layer for the endpoint
detail page (models/endpoint_software.py). Read path only here —
rows are written by injector/simulate.py's seeding step directly via
this same upsert function, not through any analyst-facing write API
(there is no "install software" workflow in a SOC platform; this is
inventory data a real deployment would sync from an EDR/MDM agent).
"""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import SoftwareCategory
from app.models.endpoint_software import EndpointSoftware


async def list_endpoint_software(db: AsyncSession, tenant_id: uuid.UUID, host_id: str) -> list[EndpointSoftware]:
    """Software inventory for one host, scoped to the tenant. Empty list if none has been recorded."""
    result = await db.execute(
        select(EndpointSoftware)
        .where(EndpointSoftware.tenant_id == tenant_id, EndpointSoftware.host_id == host_id)
        .order_by(EndpointSoftware.category, EndpointSoftware.name)
    )
    return list(result.scalars().all())


async def upsert_software(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    host_id: str,
    name: str,
    version: str,
    category: SoftwareCategory,
    vulnerabilities: list[dict],
) -> EndpointSoftware:
    """
    Idempotent insert-or-update on (tenant_id, host_id, name) — re-running
    the seed simulation against an existing tenant refreshes each
    software row's version/vulnerabilities in place rather than creating
    duplicates, same idempotency convention as
    risk_scoring.recalculate_endpoint_score's upsert-into-endpoints.
    """
    result = await db.execute(
        select(EndpointSoftware).where(
            EndpointSoftware.tenant_id == tenant_id,
            EndpointSoftware.host_id == host_id,
            EndpointSoftware.name == name,
        )
    )
    row = result.scalar_one_or_none()

    if row is None:
        row = EndpointSoftware(tenant_id=tenant_id, host_id=host_id, name=name)
        db.add(row)

    row.version = version
    row.category = category
    row.vulnerabilities = vulnerabilities
    await db.commit()
    await db.refresh(row)
    return row
