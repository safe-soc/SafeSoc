"""
SafeSOC — Threat Analytics Rollup
Org-wide trend view of detected activity (SS-111): aggregates
correlation-pattern triggers across a tenant's incidents over a
rolling window, comparing the current window against the equal-length
window immediately before it (e.g. "Credential Access attempts
trending up 40% this week").

Explicitly a rollup of existing detection data, not a new CTI feed:
reuses Incident.category (SS-094, already populated by the
correlation engine at detection time) and the existing static
MITRE ATT&CK pattern mapping (core/mitre_mapping.py, SS-029) — no
OpenSearch queries, no external data source.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import CorrelationPattern
from app.core.mitre_mapping import get_mitre_technique
from app.models.incident import Incident

# Manually-created incidents (services/incidents.py:create_incident)
# have no detected chain, so category is null — excluded from the
# rollup entirely, same as everywhere else category is null-checked.
_DEFAULT_WINDOW_DAYS = 7


class CategoryTrend(BaseModel):
    category: CorrelationPattern
    mitre_tactic: str
    mitre_technique_ids: list[str]
    current_count: int
    previous_count: int
    # None when previous_count is 0 — percentage change is undefined,
    # not infinite/zero, when there was nothing to compare against.
    change_pct: Optional[float] = None


class ThreatAnalyticsResponse(BaseModel):
    window_days: int
    trends: list[CategoryTrend]


async def _category_counts(
    db: AsyncSession, tenant_id: uuid.UUID, start: datetime, end: datetime
) -> dict[CorrelationPattern, int]:
    result = await db.execute(
        select(Incident.category, func.count())
        .where(
            Incident.tenant_id == tenant_id,
            Incident.category.is_not(None),
            Incident.created_at >= start,
            Incident.created_at < end,
        )
        .group_by(Incident.category)
    )
    return {row[0]: row[1] for row in result.all()}


async def get_threat_analytics(
    db: AsyncSession, tenant_id: uuid.UUID, window_days: int = _DEFAULT_WINDOW_DAYS
) -> ThreatAnalyticsResponse:
    """Tenant-scoped rollup, newest-count-first, over the given rolling window (default 7 days) vs. the equal-length window immediately before it."""
    now = datetime.now(timezone.utc)
    current_start = now - timedelta(days=window_days)
    previous_start = now - timedelta(days=window_days * 2)

    current_counts = await _category_counts(db, tenant_id, current_start, now)
    previous_counts = await _category_counts(db, tenant_id, previous_start, current_start)

    categories = set(current_counts) | set(previous_counts)
    trends = []
    for category in categories:
        current = current_counts.get(category, 0)
        previous = previous_counts.get(category, 0)
        mitre = get_mitre_technique(category)
        change_pct = None if previous == 0 else round((current - previous) / previous * 100, 1)
        trends.append(
            CategoryTrend(
                category=category,
                mitre_tactic=mitre.tactic,
                mitre_technique_ids=list(mitre.technique_ids),
                current_count=current,
                previous_count=previous,
                change_pct=change_pct,
            )
        )

    trends.sort(key=lambda trend: trend.current_count, reverse=True)
    return ThreatAnalyticsResponse(window_days=window_days, trends=trends)
