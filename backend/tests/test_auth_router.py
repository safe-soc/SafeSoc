"""
SafeSOC — Auth Router Tests
"""

import uuid

import pytest
from fastapi.testclient import TestClient

from app.core.enums import UserRole
from app.core.exceptions import RateLimitExceededError
from app.core.security import create_access_token, decode_access_token, hash_password
from app.db.postgresql import get_db
from app.main import app
from app.models.user import User


class _FakeResult:
    def __init__(self, user):
        self._user = user

    def scalar_one_or_none(self):
        return self._user


class _FakeSession:
    """Fake AsyncSession standing in for a real DB round-trip."""

    def __init__(self, existing_user=None):
        self.existing_user = existing_user
        self.committed = False
        self.added = None

    async def execute(self, stmt):
        return _FakeResult(self.existing_user)

    def add(self, obj):
        self.added = obj

    async def commit(self):
        self.committed = True
        if self.added is not None and self.added.id is None:
            # Simulate what a real flush would assign via the column's Python-side default.
            self.added.id = uuid.uuid4()

    async def refresh(self, obj):
        pass


@pytest.fixture
def client_with_fake_db():
    """FastAPI TestClient wired to a controllable fake DB session."""
    fake_session = _FakeSession()

    async def override_get_db():
        yield fake_session

    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app), fake_session
    app.dependency_overrides.pop(get_db, None)


# ── POST /api/v1/auth/register ──────────────────────────────────

def test_register_returns_201_with_created_user_and_no_password(client_with_fake_db):
    client, _ = client_with_fake_db
    tenant_id = str(uuid.uuid4())

    response = client.post("/api/v1/auth/register", json={
        "tenant_id": tenant_id,
        "email": "alice@example.com",
        "password": "hunter2-hunter2",
    })

    assert response.status_code == 201
    body = response.json()
    assert body["email"] == "alice@example.com"
    assert body["role"] == "viewer"
    assert "password" not in body
    assert "password_hash" not in body


def test_register_rejects_duplicate_email_with_409(client_with_fake_db):
    client, fake_session = client_with_fake_db
    tenant_id = uuid.uuid4()
    fake_session.existing_user = User(
        tenant_id=tenant_id, email="alice@example.com", password_hash="x", role=UserRole.VIEWER
    )

    response = client.post("/api/v1/auth/register", json={
        "tenant_id": str(tenant_id),
        "email": "alice@example.com",
        "password": "hunter2-hunter2",
    })

    assert response.status_code == 409


# ── POST /api/v1/auth/login ─────────────────────────────────────

def test_login_returns_token_for_correct_credentials(client_with_fake_db):
    client, fake_session = client_with_fake_db
    tenant_id = uuid.uuid4()
    fake_session.existing_user = User(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        email="alice@example.com",
        password_hash=hash_password("hunter2"),
        role=UserRole.ANALYST,
    )

    response = client.post("/api/v1/auth/login", json={
        "tenant_id": str(tenant_id),
        "email": "alice@example.com",
        "password": "hunter2",
    })

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert len(body["access_token"].split(".")) == 3


def test_login_rejects_wrong_password_with_401(client_with_fake_db):
    client, fake_session = client_with_fake_db
    tenant_id = uuid.uuid4()
    fake_session.existing_user = User(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        email="alice@example.com",
        password_hash=hash_password("hunter2"),
        role=UserRole.VIEWER,
    )

    response = client.post("/api/v1/auth/login", json={
        "tenant_id": str(tenant_id),
        "email": "alice@example.com",
        "password": "wrong-password",
    })

    assert response.status_code == 401


def test_login_rejects_unknown_email_with_401(client_with_fake_db):
    client, _ = client_with_fake_db  # no existing_user configured

    response = client.post("/api/v1/auth/login", json={
        "tenant_id": str(uuid.uuid4()),
        "email": "nobody@example.com",
        "password": "hunter2",
    })

    assert response.status_code == 401


# ── SS-067: login/register rate limiting ────────────────────────

def test_login_returns_429_once_the_rate_limit_is_exceeded(client_with_fake_db, _mock_rate_limit):
    client, fake_session = client_with_fake_db
    tenant_id = uuid.uuid4()
    fake_session.existing_user = User(
        id=uuid.uuid4(), tenant_id=tenant_id, email="alice@example.com",
        password_hash=hash_password("hunter2"), role=UserRole.VIEWER,
    )
    _mock_rate_limit.side_effect = RateLimitExceededError()

    response = client.post("/api/v1/auth/login", json={
        "tenant_id": str(tenant_id),
        "email": "alice@example.com",
        "password": "hunter2",
    })

    assert response.status_code == 429


def test_register_returns_429_once_the_rate_limit_is_exceeded(client_with_fake_db, _mock_rate_limit):
    client, _ = client_with_fake_db
    _mock_rate_limit.side_effect = RateLimitExceededError()

    response = client.post("/api/v1/auth/register", json={
        "tenant_id": str(uuid.uuid4()),
        "email": "alice@example.com",
        "password": "hunter2-hunter2",
    })

    assert response.status_code == 429


# ── SS-067: password policy ──────────────────────────────────────

def test_register_rejects_a_password_shorter_than_8_characters(client_with_fake_db):
    client, _ = client_with_fake_db

    response = client.post("/api/v1/auth/register", json={
        "tenant_id": str(uuid.uuid4()),
        "email": "alice@example.com",
        "password": "short1",
    })

    assert response.status_code == 422


# ── POST /api/v1/auth/refresh ───────────────────────────────────

def test_refresh_issues_new_token_preserving_claims(client_with_fake_db):
    client, _ = client_with_fake_db
    tenant_id, user_id = uuid.uuid4(), uuid.uuid4()
    old_token = create_access_token(tenant_id, user_id, UserRole.ADMIN)

    response = client.post("/api/v1/auth/refresh", json={"token": old_token})

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"

    new_claims = decode_access_token(body["access_token"])
    assert new_claims["tenant_id"] == str(tenant_id)
    assert new_claims["user_id"] == str(user_id)
    assert new_claims["role"] == "admin"


def test_refresh_rejects_tampered_token_with_401(client_with_fake_db):
    client, _ = client_with_fake_db
    token = create_access_token(uuid.uuid4(), uuid.uuid4(), UserRole.VIEWER)
    header, payload, signature = token.split(".")
    # Flip the *first* signature char, not the last: base64url's final
    # character can carry unused padding bits, so some replacements there
    # decode to the same bytes and silently fail to tamper anything.
    tampered_signature = ("A" if signature[0] != "A" else "B") + signature[1:]
    tampered = f"{header}.{payload}.{tampered_signature}"

    response = client.post("/api/v1/auth/refresh", json={"token": tampered})

    assert response.status_code == 401
