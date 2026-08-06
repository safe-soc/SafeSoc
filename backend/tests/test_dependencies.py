"""
SafeSOC — Auth Dependency Tests
"""

import uuid

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.core.dependencies import CurrentUser, get_current_user
from app.core.enums import UserRole
from app.core.exceptions import SafeSOCError, safesoc_exception_handler
from app.core.security import create_access_token


def _build_test_app() -> FastAPI:
    """
    A throwaway app proving get_current_user() is usable via Depends(...)
    in any router, without touching any real SafeSOC router (that wiring
    is SS-016's job). Registers the same SafeSOCError handler main.py does,
    so InvalidTokenError maps to a real 401 response here too.
    """
    app = FastAPI()
    app.add_exception_handler(SafeSOCError, safesoc_exception_handler)

    @app.get("/protected")
    async def protected(current_user: CurrentUser = Depends(get_current_user)):
        return {
            "tenant_id": str(current_user.tenant_id),
            "user_id": str(current_user.user_id),
            "role": current_user.role.value,
        }

    return app


@pytest.fixture
def client():
    return TestClient(_build_test_app())


def test_missing_authorization_header_returns_401(client):
    response = client.get("/protected")

    assert response.status_code == 401


def test_valid_token_resolves_to_tenant_user_role_context(client):
    tenant_id, user_id = uuid.uuid4(), uuid.uuid4()
    token = create_access_token(tenant_id, user_id, UserRole.ANALYST)

    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    body = response.json()
    assert body["tenant_id"] == str(tenant_id)
    assert body["user_id"] == str(user_id)
    assert body["role"] == "analyst"


def test_tampered_token_returns_401(client):
    token = create_access_token(uuid.uuid4(), uuid.uuid4(), UserRole.VIEWER)
    header, payload, signature = token.split(".")
    # Flip the *first* signature char, not the last: base64url's final
    # character can carry unused padding bits, so some replacements there
    # decode to the same bytes and silently fail to tamper anything.
    tampered_signature = ("A" if signature[0] != "A" else "B") + signature[1:]
    tampered = f"{header}.{payload}.{tampered_signature}"

    response = client.get("/protected", headers={"Authorization": f"Bearer {tampered}"})

    assert response.status_code == 401


def test_malformed_authorization_header_returns_401(client):
    response = client.get("/protected", headers={"Authorization": "not-a-bearer-token"})

    assert response.status_code == 401


def test_wrong_scheme_returns_401(client):
    token = create_access_token(uuid.uuid4(), uuid.uuid4(), UserRole.VIEWER)

    response = client.get("/protected", headers={"Authorization": f"Basic {token}"})

    assert response.status_code == 401
