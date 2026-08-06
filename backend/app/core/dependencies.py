"""
SafeSOC — Auth Dependency Injection
FastAPI dependency resolving the Authorization: Bearer <JWT> header into
a (tenant_id, user_id, role) context, usable via Depends(...) in any route.
"""

import uuid
from dataclasses import dataclass

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.enums import UserRole
from app.core.exceptions import InvalidTokenError
from app.core.security import decode_access_token

_bearer_scheme = HTTPBearer(auto_error=False)


@dataclass
class CurrentUser:
    tenant_id: uuid.UUID
    user_id: uuid.UUID
    role: UserRole


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> CurrentUser:
    """
    Resolve the Authorization: Bearer <token> header to a (tenant_id, user_id, role)
    context.

    Raises:
        InvalidTokenError: (401) if the header is missing/malformed, or the
        token is tampered or expired — before the route body executes.
    """
    if credentials is None:
        raise InvalidTokenError("Missing or malformed Authorization header.")

    claims = decode_access_token(credentials.credentials)

    return CurrentUser(
        tenant_id=uuid.UUID(claims["tenant_id"]),
        user_id=uuid.UUID(claims["user_id"]),
        role=UserRole(claims["role"]),
    )
