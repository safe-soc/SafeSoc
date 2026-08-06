"""
SafeSOC — Auth API Endpoints
POST /api/v1/auth/register, /login, /refresh — registration, JWT
issuance, and token refresh.
"""

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import UserRole
from app.core.exceptions import InvalidCredentialsError
from app.core.security import create_access_token, decode_access_token, verify_password
from app.db.postgresql import get_db
from app.models.user import User
from app.schemas.auth import LoginRequest, RefreshRequest, RegisterRequest, RegisterResponse, TokenResponse
from app.services.auth import register_user

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/register", response_model=RegisterResponse, status_code=201)
async def register(payload: RegisterRequest, db: AsyncSession = Depends(get_db)):
    """Create a new user scoped to a tenant. Rejects duplicate emails within the same tenant."""
    user = await register_user(db, payload.tenant_id, payload.email, payload.password, payload.role)
    return RegisterResponse(id=user.id, tenant_id=user.tenant_id, email=user.email, role=user.role)


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)):
    """Verify credentials and issue a JWT access token."""
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
    """Issue a new access token from a still-valid existing token."""
    claims = decode_access_token(payload.token)
    token = create_access_token(
        uuid.UUID(claims["tenant_id"]),
        uuid.UUID(claims["user_id"]),
        UserRole(claims["role"]),
    )
    return TokenResponse(access_token=token)
