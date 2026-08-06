"""
SafeSOC — Auth Dependency Injection
FastAPI dependency resolving the Authorization: Bearer <JWT> header into
a (tenant_id, user_id, role) context, usable via Depends(...) in any route.
"""

import uuid
from dataclasses import dataclass
from typing import Optional

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.enums import UserRole
from app.core.exceptions import InvalidTokenError, TenantMismatchError
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


def ensure_tenant_matches(current_user: CurrentUser, candidate_tenant_id: Optional[str]) -> None:
    """
    Guard against a caller-supplied tenant_id (request body/query) diverging
    from the authenticated token's tenant. A missing/empty candidate is
    treated as "not supplied" and passes silently — the authenticated
    tenant is always the one actually used by the caller.

    Raises:
        TenantMismatchError: (403) if candidate_tenant_id is present and
        doesn't match current_user.tenant_id.
    """
    if not candidate_tenant_id:
        return
    try:
        matches = uuid.UUID(candidate_tenant_id) == current_user.tenant_id
    except ValueError:
        matches = False
    if not matches:
        raise TenantMismatchError()
