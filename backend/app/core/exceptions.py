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


async def safesoc_exception_handler(request: Request, exc: SafeSOCError):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.message, "status_code": exc.status_code},
    )