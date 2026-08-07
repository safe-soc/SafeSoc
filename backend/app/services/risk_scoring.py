"""
SafeSOC — Risk Scoring Service
Computes a 0-100 risk score for a host from its recent alerts, using
the weight constants already defined in core/config.py, mapped to one
of four risk levels per SRS §3.3. Also persists a host's current score
(SS-033) to the endpoints table.

Formula: each alert contributes severity-weighted base points, plus
bonuses for a TI-confirmed malicious indicator, an anomaly detection
above threshold, after-hours timing, and a MITRE-mapped technique.
Contributions are summed across all of a host's alerts, then the total
is decayed by how long it's been since the host's *most recent* alert
(RISK_TIME_DECAY_PER_HOUR) — "no recent activity" decays the whole
score, not each alert individually — and capped at 100.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.enums import RiskLevel, Severity
from app.models.endpoint import Endpoint


@dataclass(frozen=True)
class RiskScore:
    score: int
    level: RiskLevel


def _severity_points(severity: Severity) -> int:
    return {
        Severity.CRITICAL: settings.RISK_SCORE_CRITICAL,
        Severity.HIGH: settings.RISK_SCORE_HIGH,
        Severity.MEDIUM: settings.RISK_SCORE_MEDIUM,
        Severity.LOW: settings.RISK_SCORE_LOW,
    }[severity]


def _parse_timestamp(value) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _is_after_hours(timestamp: datetime) -> bool:
    """
    After-hours: outside 08:00-18:00 on a weekday, or any time on a
    weekend. No per-tenant timezone concept exists anywhere else in
    this codebase, so this reads timestamps as UTC, same as every
    other timestamp comparison in the backend.
    """
    if timestamp.weekday() >= 5:  # Saturday=5, Sunday=6
        return True
    return timestamp.hour < 8 or timestamp.hour >= 18


def _level_for_score(score: int) -> RiskLevel:
    if score >= 75:
        return RiskLevel.CRITICAL
    if score >= 50:
        return RiskLevel.HIGH
    if score >= 25:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def calculate_risk_score(alerts: list[dict], *, now: Optional[datetime] = None) -> RiskScore:
    """
    Compute a host's risk score from a set of its alerts (NormalizedLog-
    shaped dicts, e.g. as returned by db/opensearch.py:search_alerts).

    An empty alert set scores 0 (Low) — a host with no alerts carries
    no risk.
    """
    if not alerts:
        return RiskScore(score=0, level=RiskLevel.LOW)

    raw = 0
    timestamps: list[datetime] = []

    for alert in alerts:
        raw += _severity_points(Severity(alert["severity"]))

        ti_result = alert.get("ti_result")
        if ti_result and ti_result.get("is_malicious"):
            raw += settings.RISK_SCORE_TI_MALICIOUS_BONUS

        anomaly_score = alert.get("anomaly_score")
        if anomaly_score is not None and anomaly_score >= settings.ANOMALY_THRESHOLD:
            raw += settings.RISK_SCORE_ANOMALY_BONUS

        if alert.get("mitre_technique"):
            raw += settings.RISK_SCORE_MITRE_BONUS

        timestamp = _parse_timestamp(alert["timestamp"])
        timestamps.append(timestamp)
        if _is_after_hours(timestamp):
            raw += settings.RISK_SCORE_AFTER_HOURS_BONUS

    current_time = now or datetime.now(timezone.utc)
    hours_since_activity = max(0.0, (current_time - max(timestamps)).total_seconds() / 3600)
    decay_factor = max(0.0, 1 - settings.RISK_TIME_DECAY_PER_HOUR * hours_since_activity)

    score = min(100, round(raw * decay_factor))
    return RiskScore(score=score, level=_level_for_score(score))


async def recalculate_endpoint_score(
    db: AsyncSession, tenant_id: uuid.UUID, host_id: str, alerts: list[dict]
) -> Endpoint:
    """
    Compute a host's current risk score and persist it (upsert into the
    endpoints table, unique per tenant_id+host_id) — the write side of
    the scheduled recalculation task (SS-033).
    """
    risk = calculate_risk_score(alerts)

    result = await db.execute(select(Endpoint).where(Endpoint.tenant_id == tenant_id, Endpoint.host_id == host_id))
    endpoint = result.scalar_one_or_none()

    if endpoint is None:
        endpoint = Endpoint(tenant_id=tenant_id, host_id=host_id)
        db.add(endpoint)

    endpoint.risk_score = risk.score
    endpoint.risk_level = risk.level
    await db.commit()
    await db.refresh(endpoint)
    return endpoint
