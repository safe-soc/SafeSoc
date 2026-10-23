"""
SafeSOC — Auth API Endpoints
POST /api/v1/auth/register, /login, /refresh — registration, JWT
issuance, and token refresh.
"""

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import InvalidCredentialsError
from app.core.dependencies import current_user_from_token
from app.core.security import create_access_token, verify_password
from app.db.postgresql import get_db
from app.models.user import User
from app.schemas.auth import LoginRequest, RefreshRequest, RegisterRequest, RegisterResponse, TokenResponse
from app.services.auth import register_user
from app.services.rate_limit import enforce_rate_limit

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/register", response_model=RegisterResponse, status_code=201)
async def register(payload: RegisterRequest, request: Request, db: AsyncSession = Depends(get_db)):
    """Create a new user scoped to a tenant. Rejects duplicate emails within the same tenant."""
    client_ip = request.client.host if request.client else "unknown"
    await enforce_rate_limit(
        f"ratelimit:register:{client_ip}",
        max_attempts=settings.AUTH_REGISTER_RATE_LIMIT_ATTEMPTS,
        window_seconds=settings.AUTH_REGISTER_RATE_LIMIT_WINDOW_SECONDS,
    )

    user = await register_user(db, payload.tenant_id, payload.email, payload.password, payload.role)
    return RegisterResponse(id=user.id, tenant_id=user.tenant_id, email=user.email, role=user.role)


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)):
    """Verify credentials and issue a JWT access token."""
    await enforce_rate_limit(
        f"ratelimit:login:{payload.tenant_id}:{payload.email}",
        max_attempts=settings.AUTH_LOGIN_RATE_LIMIT_ATTEMPTS,
        window_seconds=settings.AUTH_LOGIN_RATE_LIMIT_WINDOW_SECONDS,
    )

    result = await db.execute(
        select(User).where(User.tenant_id == payload.tenant_id, User.email == payload.email)
    )
    user = result.scalar_one_or_none()
    if user is None or not verify_password(payload.password, user.password_hash):
        raise InvalidCredentialsError()

    token = create_access_token(user.tenant_id, user.id, user.role)
    return TokenResponse(access_token=token)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(payload: RefreshRequest):
    """Issue a new access token from a still-valid existing token whose user still exists (401 otherwise)."""
    current = await current_user_from_token(payload.token)
    token = create_access_token(current.tenant_id, current.user_id, current.role)
    return TokenResponse(access_token=token)
