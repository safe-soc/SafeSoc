"""
SafeSOC — NormalizedLog Schema
The universal log format. Every log source converts to this schema
before any processing occurs. All downstream logic depends on this.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from app.core.enums import LogSource, LogType, Severity


class VTFlaggedEngine(BaseModel):
    """One VirusTotal engine that flagged an IP (malicious/suspicious only)."""
    engine: str
    category: str
    result: Optional[str] = None


class VTIPDetails(BaseModel):
    """
    VirusTotal's IP report beyond the headline counters, taken from the
    same ip_addresses/{ip} response lookup_ip already fetches — no
    extra API call. Every field is defaulted so a sparse response (or
    an older cached row) never fails validation.
    """
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    total: int = 0
    reputation: Optional[int] = None
    asn: Optional[int] = None
    as_owner: Optional[str] = None
    network: Optional[str] = None
    country: Optional[str] = None
    last_analysis_date: Optional[datetime] = None
    tags: list[str] = Field(default_factory=list)
    flagged_by: list[VTFlaggedEngine] = Field(default_factory=list)


class AbuseIPDetails(BaseModel):
    """AbuseIPDB's /check report for an IP, from the call lookup_ip already makes."""
    confidence: int = 0
    total_reports: int = 0
    num_distinct_users: int = 0
    last_reported_at: Optional[datetime] = None
    isp: Optional[str] = None
    usage_type: Optional[str] = None
    domain: Optional[str] = None
    country_code: Optional[str] = None
    hostnames: list[str] = Field(default_factory=list)
    is_tor: bool = False
    is_whitelisted: Optional[bool] = None
    max_age_days: int = 90


class TIResult(BaseModel):
    """Threat intelligence enrichment result for a single indicator."""
    source_ip: Optional[str] = None
    file_hash: Optional[str] = None
    domain: Optional[str] = None
    vt_malicious: int = 0
    vt_total: int = 0
    abuse_confidence: int = 0
    abuse_total_reports: int = 0
    is_malicious: bool = False
    tags: list[str] = Field(default_factory=list)
    # Per-provider IP details, kept separate so the enrichment merge can
    # carry each one from its own provider. None for hash lookups, for a
    # provider that returned nothing, and for ti_cache rows written
    # before these fields existed.
    vt: Optional[VTIPDetails] = None
    abuse: Optional[AbuseIPDetails] = None
    # When the provider call that produced this result actually ran
    # (set by services/enrichment.py::_get_or_fetch). Cache hits and
    # stale fallbacks keep the stored value; None on rows written before
    # this field existed and on the merged per-alert result.
    fetched_at: Optional[datetime] = None


class NormalizedLog(BaseModel):
    """
    Universal security event schema.
    Every log source (Wazuh, AWS, Synthetic) converts to this format.
    """

    # ── Identity ──────────────────────────────────
    alert_id: str = Field(default_factory=lambda: str(uuid4()))
    tenant_id: str

    # ── Source ────────────────────────────────────
    source: LogSource
    log_type: LogType

    # ── Timing ────────────────────────────────────
    timestamp: datetime
    ingested_at: datetime = Field(default_factory=datetime.utcnow)

    # ── Host Context ──────────────────────────────
    host_id: str
    host_ip: str
    host_os: Optional[str] = None  # linux, windows, macos, cloud

    # ── Event Context ─────────────────────────────
    user: str = "unknown"
    action: str
    description: str
    severity: Severity

    # ── Detection Context ─────────────────────────
    rule_id: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None

    # ── Network Context ───────────────────────────
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None

    # ── File Context ──────────────────────────────
    file_path: Optional[str] = None
    file_hash: Optional[str] = None
    file_size: Optional[int] = None

    # ── Process Context ───────────────────────────
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    parent_process: Optional[str] = None
    command_line: Optional[str] = None

    # ── Raw Data ──────────────────────────────────
    raw_log: str = "{}"

    # ── Enrichment (populated after ingestion) ────
    ti_enriched: bool = False
    ti_result: Optional[TIResult] = None
    risk_score: int = 0
    anomaly_score: Optional[float] = None

    model_config = {
        "json_schema_extra": {
            "example": {
                "alert_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "tenant_id": "acme-corp",
                "source": "wazuh",
                "log_type": "authentication",
                "timestamp": "2026-05-12T02:47:11Z",
                "host_id": "DESKTOP-042",
                "host_ip": "192.168.1.42",
                "host_os": "windows",
                "user": "john.doe",
                "action": "failed_login",
                "description": "Failed SSH authentication attempt",
                "severity": "high",
                "rule_id": "5710",
                "mitre_technique": "T1110",
                "mitre_tactic": "Credential Access",
                "source_ip": "45.33.32.156",
                "source_port": 48221,
                "destination_port": 22,
                "protocol": "tcp",
                "raw_log": "{\"original\": \"wazuh alert json\"}",
            }
        }
    }