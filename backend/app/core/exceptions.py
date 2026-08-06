"""
SafeSOC — Custom Exceptions
"""

from fastapi import Request
from fastapi.responses import JSONResponse


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


async def safesoc_exception_handler(request: Request, exc: SafeSOCError):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.message, "status_code": exc.status_code},
    )