"""
SafeSOC — Auth Dependency Injection
FastAPI dependency resolving the Authorization: Bearer <JWT> header into
a (tenant_id, user_id, role) context, usable via Depends(...) in any route.
Also provides require_role(...) for RBAC enforcement (SRS §3.2): admin >
analyst > viewer, each tier including everything the tiers below it can do.
"""

import time
import uuid
from dataclasses import dataclass
from typing import Callable, Optional

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.enums import UserRole
from app.core.exceptions import InsufficientRoleError, InvalidTokenError, TenantMismatchError
from app.core.security import decode_access_token
from app.db.postgresql import async_session_factory
from app.models.user import User

_bearer_scheme = HTTPBearer(auto_error=False)

# A valid signature isn't enough: after a database reset (or a user's
# deletion) an old token still verifies, and every audit write for it
# then fails on audit_log_actor_user_id_fkey. So the token's user must
# still exist, in the token's tenant. One primary-key lookup, cached
# briefly per (tenant, user) so a burst of requests costs one query.
USER_CHECK_CACHE_SECONDS = 5.0
_USER_CHECK_CACHE_MAX_ENTRIES = 10_000
_user_check_cache: dict[tuple[uuid.UUID, uuid.UUID], tuple[bool, float]] = {}


async def user_exists(tenant_id: uuid.UUID, user_id: uuid.UUID) -> bool:
    """True if `user_id` is a user of `tenant_id` right now (cached for USER_CHECK_CACHE_SECONDS)."""
    key = (tenant_id, user_id)
    now = time.monotonic()
    cached = _user_check_cache.get(key)
    if cached is not None and cached[1] > now:
        return cached[0]

    async with async_session_factory() as db:
        user = await db.get(User, user_id)
    exists = user is not None and user.tenant_id == tenant_id

    if len(_user_check_cache) >= _USER_CHECK_CACHE_MAX_ENTRIES:
        _user_check_cache.clear()
    _user_check_cache[key] = (exists, now + USER_CHECK_CACHE_SECONDS)
    return exists


async def current_user_from_token(token: str) -> "CurrentUser":
    """
    Decode a JWT AND confirm its user still exists in its tenant — shared
    by get_current_user and the WebSocket endpoint (routers/ws.py).

    Raises:
        InvalidTokenError: (401) tampered/expired token, or a deleted
        user / tenant mismatch.
    """
    claims = decode_access_token(token)
    current = CurrentUser(
        tenant_id=uuid.UUID(claims["tenant_id"]),
        user_id=uuid.UUID(claims["user_id"]),
        role=UserRole(claims["role"]),
    )
    if not await user_exists(current.tenant_id, current.user_id):
        raise InvalidTokenError("This session's user no longer exists. Please sign in again.")
    return current


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
        InvalidTokenError: (401) if the header is missing/malformed, the
        token is tampered or expired, or its user no longer exists in its
        tenant — before the route body executes.
    """
    if credentials is None:
        raise InvalidTokenError("Missing or malformed Authorization header.")

    return await current_user_from_token(credentials.credentials)


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
