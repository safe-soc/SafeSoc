"""
SafeSOC — Shared Enums
Single source of truth for all fixed value sets.
Used by Pydantic schemas, OpenSearch mappings, SQLAlchemy models,
and frontend TypeScript types.
"""

from enum import Enum


class LogSource(str, Enum):
    """Origin of a security log."""
    WAZUH = "wazuh"
    SYNTHETIC = "synthetic"
    AWS_CLOUDTRAIL = "aws_cloudtrail"
    AWS_GUARDDUTY = "aws_guardduty"
    # A CloudLens Finding (IAM risk-scan result) is a materially different
    # kind of record from a CloudTrail API-call log — a static
    # misconfiguration finding, not a runtime event — so it gets its own
    # source value (SS-038) rather than being mislabeled as CloudTrail.
    CLOUDLENS = "cloudlens"


class LogType(str, Enum):
    """Category of security event."""
    AUTHENTICATION = "authentication"
    NETWORK = "network"
    PROCESS = "process"
    FILE = "file"
    PRIVILEGE = "privilege"
    CLOUD = "cloud"
    SYSTEM = "system"


class Severity(str, Enum):
    """Alert severity level."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, Enum):
    """Incident lifecycle states."""
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class UserRole(str, Enum):
    """Role-based access control levels."""
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class TIProvider(str, Enum):
    """Threat intelligence sources."""
    VIRUSTOTAL = "virustotal"
    ABUSEIPDB = "abuseipdb"


class IndicatorType(str, Enum):
    """Types of threat indicators."""
    IP = "ip"
    FILE_HASH = "file_hash"
    DOMAIN = "domain"


class CorrelationPattern(str, Enum):
    """Attack chain patterns detected by the correlation engine (SRS §3.3)."""
    CREDENTIAL_BRUTE_FORCE = "credential_brute_force"
    SUCCESSFUL_COMPROMISE = "successful_compromise"
    RECON_TO_EXPLOITATION = "recon_to_exploitation"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"


class RiskLevel(str, Enum):
    """Endpoint risk levels a 0-100 risk score maps to (SRS §3.3)."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"