"""
SafeSOC — JWT Issuance & Validation Tests
"""

import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest

from app.core.config import settings
from app.core.enums import UserRole
from app.core.exceptions import InvalidTokenError
from app.core.security import create_access_token, decode_access_token


def test_create_access_token_embeds_tenant_user_and_role_claims():
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()

    token = create_access_token(tenant_id, user_id, UserRole.ANALYST)
    claims = decode_access_token(token)

    assert claims["tenant_id"] == str(tenant_id)
    assert claims["user_id"] == str(user_id)
    assert claims["role"] == "analyst"


def test_create_access_token_expires_per_configured_jwt_expiry_hours():
    token = create_access_token(uuid.uuid4(), uuid.uuid4(), UserRole.VIEWER)
    claims = decode_access_token(token)

    lifetime = claims["exp"] - claims["iat"]
    assert lifetime == settings.JWT_EXPIRY_HOURS * 3600


def test_decode_access_token_rejects_tampered_token_with_401():
    token = create_access_token(uuid.uuid4(), uuid.uuid4(), UserRole.VIEWER)
    header, payload, signature = token.split(".")
    tampered_signature = ("A" if signature[0] != "A" else "B") + signature[1:]
    tampered_token = f"{header}.{payload}.{tampered_signature}"

    with pytest.raises(InvalidTokenError) as exc_info:
        decode_access_token(tampered_token)

    assert exc_info.value.status_code == 401


def test_decode_access_token_rejects_expired_token_with_401():
    now = datetime.now(timezone.utc)
    expired_payload = {
        "tenant_id": str(uuid.uuid4()),
        "user_id": str(uuid.uuid4()),
        "role": UserRole.VIEWER.value,
        "iat": now - timedelta(hours=settings.JWT_EXPIRY_HOURS, minutes=5),
        "exp": now - timedelta(minutes=5),
    }
    expired_token = jwt.encode(expired_payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)

    with pytest.raises(InvalidTokenError) as exc_info:
        decode_access_token(expired_token)

    assert exc_info.value.status_code == 401


def test_decode_access_token_rejects_token_signed_with_wrong_secret():
    payload = {
        "tenant_id": str(uuid.uuid4()),
        "user_id": str(uuid.uuid4()),
        "role": UserRole.VIEWER.value,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
    }
    forged_token = jwt.encode(payload, "a-different-secret", algorithm=settings.JWT_ALGORITHM)

    with pytest.raises(InvalidTokenError):
        decode_access_token(forged_token)
