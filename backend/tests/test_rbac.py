"""
SafeSOC — RBAC Enforcement Tests (SS-017)
Proves require_role(...) enforces the admin > analyst > viewer
hierarchy (SRS §3.2) on one endpoint per tier.
"""

import uuid

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.core.dependencies import CurrentUser, require_role
from app.core.enums import UserRole
from app.core.exceptions import SafeSOCError, safesoc_exception_handler
from app.core.security import create_access_token


def _build_test_app() -> FastAPI:
    """
    A throwaway app with one endpoint per role tier, proving require_role(...)
    is usable via Depends(...) in any router without touching a real one
    (mirrors SS-015's precedent for get_current_user). Registers the same
    SafeSOCError handler main.py does, so InsufficientRoleError maps to a
    real 403 here too.
    """
    app = FastAPI()
    app.add_exception_handler(SafeSOCError, safesoc_exception_handler)

    @app.get("/viewer-or-above")
    async def viewer_or_above(current_user: CurrentUser = Depends(require_role(UserRole.VIEWER))):
        return {"role": current_user.role.value}

    @app.get("/analyst-or-above")
    async def analyst_or_above(current_user: CurrentUser = Depends(require_role(UserRole.ANALYST))):
        return {"role": current_user.role.value}

    @app.get("/admin-only")
    async def admin_only(current_user: CurrentUser = Depends(require_role(UserRole.ADMIN))):
        return {"role": current_user.role.value}

    return app


@pytest.fixture
def client():
    return TestClient(_build_test_app())


def _headers_for(role: UserRole) -> dict:
    token = create_access_token(uuid.uuid4(), uuid.uuid4(), role)
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.parametrize(
    "role,endpoint,expected_status",
    [
        # Viewer: read-only tier — allowed at its own tier, blocked above.
        (UserRole.VIEWER, "/viewer-or-above", 200),
        (UserRole.VIEWER, "/analyst-or-above", 403),
        (UserRole.VIEWER, "/admin-only", 403),
        # Analyst: allowed at viewer and analyst tiers, blocked from admin-only.
        (UserRole.ANALYST, "/viewer-or-above", 200),
        (UserRole.ANALYST, "/analyst-or-above", 200),
        (UserRole.ANALYST, "/admin-only", 403),
        # Admin: full access, allowed everywhere.
        (UserRole.ADMIN, "/viewer-or-above", 200),
        (UserRole.ADMIN, "/analyst-or-above", 200),
        (UserRole.ADMIN, "/admin-only", 200),
    ],
)
def test_require_role_enforces_the_hierarchy(client, role, endpoint, expected_status):
    response = client.get(endpoint, headers=_headers_for(role))

    assert response.status_code == expected_status


def test_under_privileged_role_gets_403_not_401(client):
    response = client.get("/admin-only", headers=_headers_for(UserRole.VIEWER))

    assert response.status_code == 403
    assert response.json()["status_code"] == 403


def test_missing_token_gets_401_not_403(client):
    response = client.get("/admin-only")

    assert response.status_code == 401
