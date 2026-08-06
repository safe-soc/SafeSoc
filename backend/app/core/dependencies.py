"""
SafeSOC — Auth Dependency Injection
FastAPI dependency resolving the Authorization: Bearer <JWT> header into
a (tenant_id, user_id, role) context, usable via Depends(...) in any route.
Also provides require_role(...) for RBAC enforcement (SRS §3.2): admin >
analyst > viewer, each tier including everything the tiers below it can do.
"""

import uuid
from dataclasses import dataclass
from typing import Callable, Optional

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.enums import UserRole
from app.core.exceptions import InsufficientRoleError, InvalidTokenError, TenantMismatchError
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


# Ordered lowest-to-highest per SRS §3.2: viewers are read-only, analysts
# additionally get alert/incident/investigation access, admins get everything.
_ROLE_RANK = {
    UserRole.VIEWER: 0,
    UserRole.ANALYST: 1,
    UserRole.ADMIN: 2,
}


def require_role(minimum_role: UserRole) -> Callable[[CurrentUser], CurrentUser]:
    """
    Dependency factory: Depends(require_role(UserRole.ANALYST)) allows
    ANALYST and ADMIN (everything at or above the given tier), blocking
    lower roles. Reuses get_current_user, so authentication (401) is
    still checked first — a missing/invalid token never reaches the role
    check.

    Raises:
        InsufficientRoleError: (403) if the authenticated user's role is
        below minimum_role.
    """
    def _require_role(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if _ROLE_RANK[current_user.role] < _ROLE_RANK[minimum_role]:
            raise InsufficientRoleError(current_user.role, minimum_role)
        return current_user

    return _require_role
