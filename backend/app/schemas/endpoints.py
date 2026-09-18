"""
SafeSOC — Endpoint Schemas
Response models for the endpoints listing API (SS-034) and the
endpoint software/vulnerability inventory (demo simulation).
"""

import uuid
from datetime import datetime

from pydantic import BaseModel

from app.core.enums import RiskLevel, SoftwareCategory


class EndpointResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    host_id: str
    risk_score: int
    risk_level: RiskLevel
    updated_at: datetime


class VulnerabilityResponse(BaseModel):
    id: str
    severity: str
    title: str
    # True for a clearly-labeled demo/synthetic identifier (not a real
    # CVE) — see injector/simulate.py's VULNERABILITY_CATALOG for the
    # real-CVE-only-when-genuinely-known sourcing rule this reflects.
    is_synthetic: bool = True


class EndpointSoftwareResponse(BaseModel):
    id: uuid.UUID
    host_id: str
    name: str
    version: str
    category: SoftwareCategory
    vulnerabilities: list[VulnerabilityResponse]
    updated_at: datetime
