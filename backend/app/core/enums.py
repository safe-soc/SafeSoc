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


class DismissReason(str, Enum):
    """Why an analyst dismissed an alert (stored as text on alert_annotations.dismiss_reason)."""
    FALSE_POSITIVE = "false_positive"
    EXPECTED_ACTIVITY = "expected_activity"
    DUPLICATE = "duplicate"
    OTHER = "other"


class TriageStatus(str, Enum):
    """Alerts-page triage filter. An alert with no annotation row is untriaged."""
    UNTRIAGED = "untriaged"
    ACKNOWLEDGED = "acknowledged"
    DISMISSED = "dismissed"


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


class SoftwareCategory(str, Enum):
    """Broad category of an inventoried piece of endpoint software (endpoint detail page)."""
    OPERATING_SYSTEM = "operating_system"
    BROWSER = "browser"
    PRODUCTIVITY = "productivity"
    RUNTIME = "runtime"
    REMOTE_ADMIN = "remote_admin"
    SECURITY = "security"
    OTHER = "other"


class VulnerabilitySeverity(str, Enum):
    """Severity of a software vulnerability — mirrors Severity's 4-tier vocabulary for UI consistency."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


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


class FindingCategory(str, Enum):
    """
    An investigation-session finding's certainty state. CONFIRMED is
    reachable only via an explicit analyst action (never set by the AI
    directly, never auto-derived from an LLM answer) — see
    services/investigation_session.py's own module docstring for why
    this distinction is load-bearing, not cosmetic.
    """
    CONFIRMED = "confirmed"
    HYPOTHESIS = "hypothesis"
    OPEN_QUESTION = "open_question"  # something not yet known — distinct from InvestigationAction (something to DO)


class FindingOrigin(str, Enum):
    """Who proposed a finding — the AI can only ever write ai_suggested; only an analyst action produces analyst."""
    ANALYST = "analyst"
    AI_SUGGESTED = "ai_suggested"


class InvestigationActionStatus(str, Enum):
    """Lifecycle of an investigation action (something an analyst should DO — distinct from an open question, something not yet KNOWN)."""
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"


class Intent(str, Enum):
    """
    The 8 natural-language query intents the investigation assistant
    supports (SRS §3.3, SS-044).
    """
    AUTH_FAILURES = "auth_failures"
    IP_ACTIVITY = "ip_activity"
    ENDPOINT_SNAPSHOT = "endpoint_snapshot"
    TOP_ALERTS = "top_alerts"
    USER_ACTIVITY = "user_activity"
    CLOUD_EVENTS = "cloud_events"
    RISKY_ENDPOINTS = "risky_endpoints"
    ATTACK_CHAIN_STATUS = "attack_chain_status"
    # "Anything suspicious today?" / "give me a summary" — a tenant-wide
    # overview. Answered with the TOP_ALERTS tool until it has its own.
    OVERVIEW = "overview"
    # Fallback for queries that don't confidently match any of the 8
    # supported intents (SS-044 AC) — never silently guessed as one.
    UNKNOWN = "unknown"


class QueryResolution(str, Enum):
    """How the Investigate chat handles a query (services/investigation.py::resolve_query)."""
    TOOL = "tool"                      # call the intent's MCP tool
    UNKNOWN = "unknown"                # unclassified and not a follow-up: help text
    NOISE = "noise"                    # "hi", "?", "thanks" — no topic at all
    CLARIFY = "clarify"                # intent known, a required parameter isn't
    ACTION_REQUEST = "action_request"  # "block / isolate / disable…" — chat can't act
    THREAT_INTEL = "threat_intel"      # "check on VirusTotal" with no IP to look up
    REFUSAL = "refusal"                # prompt injection / cross-tenant phrasing


class ComplianceStatus(str, Enum):
    """
    Internal evidence-classification vocabulary for the Compliance
    Center (core/compliance_mapping.py, services/compliance.py). This
    is NEVER a legal-compliance determination — it only describes
    whether SafeSOC telemetry contains evidence consistent with a
    given regulatory requirement. See docs/compliance.md. The frontend
    must render only the four approved user-facing phrasings mapped
    from these values ("Evidence available", "Control appears
    supported", "Evidence gap", "Not assessable from SafeSOC
    telemetry") — never "compliant"/"non-compliant" in any form.
    """
    EVIDENCE_AVAILABLE = "evidence_available"
    PARTIALLY_SUPPORTED = "partially_supported"
    GAP = "gap"
    NOT_ASSESSABLE = "not_assessable"


class ComplianceFramework(str, Enum):
    """Regulatory frameworks covered by the Compliance Center (core/compliance_mapping.py)."""
    DPDP_ACT_2023 = "dpdp_act_2023"
    CERT_IN_DIRECTIONS_2022 = "cert_in_directions_2022"
    DPIIT = "dpiit"


class SoarActionType(str, Enum):
    """
    The complete, closed set of SOAR-executable actions (core/
    soar_policy.py, core/soar_playbooks.py). Deliberately excludes any
    "never autonomous" action (delete evidence, delete accounts,
    destructive filesystem actions, irreversible production changes) —
    those are not members of this enum at all, so there is no value
    for a policy check, an AI recommendation, or a malicious caller to
    even target. See core/soar_policy.py's module docstring.
    """
    # AUTOMATIC
    COLLECT_ADDITIONAL_EVIDENCE = "collect_additional_evidence"
    CREATE_INVESTIGATION_ACTION = "create_investigation_action"
    ENRICH_INDICATOR = "enrich_indicator"
    ADD_INCIDENT_NOTE = "add_incident_note"
    INCREASE_INCIDENT_PRIORITY = "increase_incident_priority"
    # APPROVAL_REQUIRED
    ISOLATE_ENDPOINT = "isolate_endpoint"
    DISABLE_ACCOUNT = "disable_account"
    BLOCK_INDICATOR = "block_indicator"
    TERMINATE_PROCESS = "terminate_process"
    REVOKE_CREDENTIALS = "revoke_credentials"


class AutonomyClass(str, Enum):
    """
    Whether a SoarActionType may execute without a human in the loop.
    Only two members, by design — see core/soar_policy.py. There is no
    NEVER_AUTONOMOUS member: an action that must never run autonomously
    is simply not in SoarActionType at all, not a third value here.
    """
    AUTOMATIC = "automatic"
    APPROVAL_REQUIRED = "approval_required"


class SoarRunStatus(str, Enum):
    """Lifecycle of a SoarPlaybookRun (services/soar.py's state machine)."""
    PENDING = "pending"
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SoarActionStatus(str, Enum):
    """Lifecycle of one SoarActionExecution (services/soar.py's state machine)."""
    PENDING = "pending"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class SoarTriggerSource(str, Enum):
    """What caused a SoarPlaybookRun to be created."""
    AUTO_TRIGGER = "auto_trigger"
    MANUAL = "manual"
    AI_RECOMMENDED = "ai_recommended"


class RecommendationSource(str, Enum):
    """Who/what proposed a specific SoarActionExecution — mirrors FindingOrigin's analyst-vs-ai_suggested split."""
    ANALYST = "analyst"
    AI_SUGGESTED = "ai_suggested"
    PLAYBOOK_AUTO = "playbook_auto"


class SoarVerificationStatus(str, Enum):
    """Whether a completed SoarActionExecution's real-world effect (in the simulated environment) has been confirmed."""
    NOT_VERIFIED = "not_verified"
    VERIFIED = "verified"
    VERIFICATION_FAILED = "verification_failed"