"""
SafeSOC — Authentication Service
User registration: tenant-scoped uniqueness and bcrypt password hashing.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import UserRole
from app.core.exceptions import DuplicateEmailError
from app.core.security import hash_password
from app.models.user import User
from app.utils.logger import get_logger

logger = get_logger(__name__)


async def register_user(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    email: str,
    password: str,
    role: UserRole = UserRole.VIEWER,
) -> User:
    """
    Create a new User row scoped to a tenant, hashing the password with bcrypt.

    Raises:
        DuplicateEmailError: if the tenant already has a user with this email.
    """
    result = await db.execute(
        select(User).where(User.tenant_id == tenant_id, User.email == email)
    )
    if result.scalar_one_or_none() is not None:
        raise DuplicateEmailError(email)

    user = User(
        tenant_id=tenant_id,
        email=email,
        password_hash=hash_password(password),
        role=role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    logger.info("User registered", tenant_id=str(tenant_id), email=email, role=role.value)
    return user
