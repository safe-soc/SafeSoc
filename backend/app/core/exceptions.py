"""
SafeSOC — Custom Exceptions
"""

from fastapi import Request
from fastapi.responses import JSONResponse

from app.core.enums import UserRole


class SafeSOCError(Exception):
    """Base exception for SafeSOC."""
    def __init__(self, message: str, status_code: int = 500):
        self.message = message
        self.status_code = status_code


class IngestionError(SafeSOCError):
    """Raised when log ingestion fails."""
    def __init__(self, message: str):
        super().__init__(message, status_code=422)


class OpenSearchError(SafeSOCError):
    """Raised when OpenSearch operations fail."""
    def __init__(self, message: str):
        super().__init__(message, status_code=503)


class DuplicateEmailError(SafeSOCError):
    """Raised when a tenant already has a user registered with the given email."""
    def __init__(self, email: str):
        super().__init__(f"A user with email '{email}' already exists for this tenant.", status_code=409)


class InvalidTokenError(SafeSOCError):
    """Raised when a JWT is missing, tampered, or expired."""
    def __init__(self, message: str = "Invalid or expired token."):
        super().__init__(message, status_code=401)


class InvalidCredentialsError(SafeSOCError):
    """Raised when login credentials don't match any user."""
    def __init__(self, message: str = "Invalid email or password."):
        super().__init__(message, status_code=401)


class TenantMismatchError(SafeSOCError):
    """Raised when a request's tenant_id doesn't match the authenticated token's tenant."""
    def __init__(self, message: str = "tenant_id does not match the authenticated tenant."):
        super().__init__(message, status_code=403)


class InsufficientRoleError(SafeSOCError):
    """Raised when an authenticated user's role doesn't meet an endpoint's minimum required role."""
    def __init__(self, actual_role: UserRole, required_role: UserRole):
        super().__init__(
            f"Role '{actual_role.value}' does not meet the required minimum role '{required_role.value}'.",
            status_code=403,
        )


class IncidentNotFoundError(SafeSOCError):
    """Raised when an incident doesn't exist, or exists but belongs to a different tenant."""
    def __init__(self, incident_id):
        super().__init__(f"Incident '{incident_id}' not found.", status_code=404)


class InvalidStateTransitionError(SafeSOCError):
    """Raised when an incident status transition isn't allowed by the lifecycle state machine."""
    def __init__(self, from_status, to_status):
        super().__init__(
            f"Cannot transition an incident from '{from_status.value}' to '{to_status.value}'.",
            status_code=409,
        )


class AssigneeNotFoundError(SafeSOCError):
    """Raised when an incident assignment names a user who doesn't exist, or exists but belongs to a different tenant (SS-095) — same indistinguishable-404 pattern as IncidentNotFoundError."""
    def __init__(self, user_id):
        super().__init__(f"Assignee '{user_id}' not found.", status_code=404)


class RateLimitExceededError(SafeSOCError):
    """Raised when a caller exceeds an endpoint's configured rate limit."""
    def __init__(self, message: str = "Too many attempts. Please try again later."):
        super().__init__(message, status_code=429)


class InvalidServiceTokenError(SafeSOCError):
    """Raised when a service-to-service caller's X-Service-Token header is missing or wrong."""
    def __init__(self, message: str = "Invalid or missing service token."):
        super().__init__(message, status_code=401)


class ReportNotFoundError(SafeSOCError):
    """Raised when a report doesn't exist under the caller's own tenant — including one that belongs to a different tenant."""
    def __init__(self, filename: str):
        super().__init__(f"Report '{filename}' not found.", status_code=404)


class InvestigationSessionNotFoundError(SafeSOCError):
    """
    Raised when an investigation session doesn't exist, or exists but
    doesn't belong to the given (tenant-verified) incident — including
    a real session_id that belongs to a different incident (same
    tenant or not). A session_id alone is never sufficient to reach a
    session; the incident_id it's requested under must also match.
    """
    def __init__(self, session_id):
        super().__init__(f"Investigation session '{session_id}' not found.", status_code=404)


class InvestigationFindingNotFoundError(SafeSOCError):
    """Raised when a finding doesn't exist, or doesn't belong to the given (already-verified) session."""
    def __init__(self, finding_id):
        super().__init__(f"Investigation finding '{finding_id}' not found.", status_code=404)


class InvestigationActionNotFoundError(SafeSOCError):
    """Raised when an action doesn't exist, or doesn't belong to the given (already-verified) session."""
    def __init__(self, action_id):
        super().__init__(f"Investigation action '{action_id}' not found.", status_code=404)


class ComplianceRequirementNotFoundError(SafeSOCError):
    """Raised when a requirement id doesn't match any entry in core/compliance_mapping.py's static list."""
    def __init__(self, requirement_id: str):
        super().__init__(f"Compliance requirement '{requirement_id}' not found.", status_code=404)


class SoarPlaybookNotFoundError(SafeSOCError):
    """Raised when a playbook_id doesn't match any entry in core/soar_playbooks.py's static list."""
    def __init__(self, playbook_id: str):
        super().__init__(f"SOAR playbook '{playbook_id}' not found.", status_code=404)


class SoarRunNotFoundError(SafeSOCError):
    """
    Raised when a SOAR playbook run doesn't exist, or exists but
    doesn't belong to the given (already tenant-verified) incident —
    including a real run_id that belongs to a different incident (same
    tenant or not). A run_id alone is never sufficient to reach a run.
    """
    def __init__(self, run_id):
        super().__init__(f"SOAR playbook run '{run_id}' not found.", status_code=404)


class InvalidSoarRunTransitionError(SafeSOCError):
    """Raised when a SoarPlaybookRun status transition isn't allowed by its state machine (services/soar.py)."""
    def __init__(self, from_status, to_status):
        super().__init__(
            f"Cannot transition a SOAR playbook run from '{from_status.value}' to '{to_status.value}'.",
            status_code=409,
        )


class InvalidSoarActionTransitionError(SafeSOCError):
    """
    Raised when a SoarActionExecution status transition isn't allowed
    by its state machine (services/soar.py) — including an
    APPROVAL_REQUIRED action attempting PENDING -> EXECUTING directly,
    which the status graph alone wouldn't catch.
    """
    def __init__(self, from_status, to_status):
        super().__init__(
            f"Cannot transition a SOAR action execution from '{from_status.value}' to '{to_status.value}'.",
            status_code=409,
        )


class SoarActionParameterError(SafeSOCError):
    """Raised when a playbook step's resolved parameters fail validation against its action_type's parameter model (app/schemas/soar.py)."""
    def __init__(self, action_type, detail: str):
        super().__init__(f"Invalid parameters for SOAR action '{action_type.value}': {detail}", status_code=422)


class SoarActionExecutionNotFoundError(SafeSOCError):
    """Raised when a SoarActionExecution id doesn't exist — an internal consistency failure inside the dispatcher (services/soar_execution.py), not a normal caller-facing lookup."""
    def __init__(self, action_id):
        super().__init__(f"SOAR action execution '{action_id}' not found.", status_code=404)


class SoarPolicyViolationError(SafeSOCError):
    """
    Raised when services/soar_execution.py's dispatcher re-checks
    core/soar_policy.py::classify() immediately before executing an
    action and finds it is not AUTOMATIC. This is the hard safety
    backstop — it should never fire in normal operation (only
    AUTOMATIC actions are ever queued), and firing indicates an
    attempted or actual policy bypass, not routine control flow.
    """
    def __init__(self, action_type, autonomy_class):
        super().__init__(
            f"SOAR action '{action_type.value}' is classified '{autonomy_class.value}', not automatic — refusing to execute it without approval.",
            status_code=403,
        )


class InvalidIndicatorError(SafeSOCError):
    """A threat-intel refresh was requested for a value that isn't a public (globally routable) IP."""
    def __init__(self, indicator: str):
        super().__init__(f"'{indicator}' is not a public IP address, so it can't be looked up.", status_code=400)


class IndicatorNotInIncidentError(SafeSOCError):
    """The IP isn't among the incident's evidence IPs — ti_cache is global, so this is the tenant-scoping check."""
    def __init__(self, indicator: str):
        super().__init__(f"IP '{indicator}' is not part of this incident's evidence.", status_code=404)


class ThreatIntelRefreshCooldownError(SafeSOCError):
    def __init__(self):
        super().__init__("Refreshed recently — try again in a minute.", status_code=429)


async def safesoc_exception_handler(request: Request, exc: SafeSOCError):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.message, "status_code": exc.status_code},
    )