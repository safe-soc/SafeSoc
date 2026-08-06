"""
SafeSOC — Auth Schemas
Request/response models for registration, login, and token refresh.
"""

import uuid

from pydantic import BaseModel

from app.core.enums import UserRole


class RegisterRequest(BaseModel):
    tenant_id: uuid.UUID
    email: str
    password: str
    role: UserRole = UserRole.VIEWER

    model_config = {
        "json_schema_extra": {
            "example": {
                "tenant_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "email": "analyst@acme-corp.com",
                "password": "correct-horse-battery-staple",
                "role": "analyst",
            }
        }
    }


class RegisterResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    email: str
    role: UserRole


class LoginRequest(BaseModel):
    tenant_id: uuid.UUID
    email: str
    password: str

    model_config = {
        "json_schema_extra": {
            "example": {
                "tenant_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "email": "analyst@acme-corp.com",
                "password": "correct-horse-battery-staple",
            }
        }
    }


class RefreshRequest(BaseModel):
    token: str

    model_config = {
        "json_schema_extra": {
            "example": {
                "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            }
        }
    }


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
