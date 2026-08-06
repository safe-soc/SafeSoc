"""
SafeSOC — Password Hashing & JWT Issuance/Validation
bcrypt-based password hashing plus JWT access-token issuance and
verification. Passwords are never stored or logged in plaintext
anywhere in the codebase.
"""

import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from app.core.config import settings
from app.core.enums import UserRole
from app.core.exceptions import InvalidTokenError


def hash_password(password: str) -> str:
    """Hash a plaintext password for storage."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a plaintext password against a stored bcrypt hash."""
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def create_access_token(tenant_id: uuid.UUID, user_id: uuid.UUID, role: UserRole) -> str:
    """Issue a JWT embedding tenant_id, user_id, and role, expiring per JWT_EXPIRY_HOURS."""
    now = datetime.now(timezone.utc)
    payload = {
        "tenant_id": str(tenant_id),
        "user_id": str(user_id),
        "role": role.value,
        "iat": now,
        "exp": now + timedelta(hours=settings.JWT_EXPIRY_HOURS),
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    """
    Verify and decode a JWT, returning its claims.

    Raises:
        InvalidTokenError: if the token is missing, tampered, or expired.
    """
    try:
        return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except jwt.PyJWTError as e:
        raise InvalidTokenError(str(e)) from e
