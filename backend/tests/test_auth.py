"""
SafeSOC — Auth Service Tests
"""

import uuid

import pytest

from app.core.enums import UserRole
from app.core.exceptions import DuplicateEmailError
from app.core.security import verify_password
from app.models.user import User
from app.services.auth import register_user


class _FakeResult:
    def __init__(self, existing_user):
        self._existing_user = existing_user

    def scalar_one_or_none(self):
        return self._existing_user


class _FakeSession:
    """Fake AsyncSession standing in for a real DB round-trip."""

    def __init__(self, existing_user=None):
        self._existing_user = existing_user
        self.committed = False
        self.added = None

    async def execute(self, stmt):
        return _FakeResult(self._existing_user)

    def add(self, obj):
        self.added = obj

    async def commit(self):
        self.committed = True

    async def refresh(self, obj):
        pass


@pytest.mark.asyncio
async def test_register_user_creates_user_with_hashed_password():
    session = _FakeSession(existing_user=None)
    tenant_id = uuid.uuid4()

    user = await register_user(session, tenant_id, "alice@example.com", "hunter2")

    assert session.committed is True
    assert user.tenant_id == tenant_id
    assert user.email == "alice@example.com"
    assert user.role == UserRole.VIEWER
    assert user.password_hash != "hunter2"
    assert verify_password("hunter2", user.password_hash) is True


@pytest.mark.asyncio
async def test_register_user_rejects_duplicate_email_within_same_tenant():
    tenant_id = uuid.uuid4()
    existing = User(tenant_id=tenant_id, email="alice@example.com", password_hash="x", role=UserRole.VIEWER)
    session = _FakeSession(existing_user=existing)

    with pytest.raises(DuplicateEmailError):
        await register_user(session, tenant_id, "alice@example.com", "hunter2")

    assert session.committed is False
