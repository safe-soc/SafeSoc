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