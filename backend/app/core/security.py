"""
SafeSOC — Password Hashing
bcrypt-based password hashing and verification. Passwords are never
stored or logged in plaintext anywhere in the codebase.
"""

import bcrypt


def hash_password(password: str) -> str:
    """Hash a plaintext password for storage."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a plaintext password against a stored bcrypt hash."""
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
