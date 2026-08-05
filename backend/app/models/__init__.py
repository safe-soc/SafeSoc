"""
SafeSOC — SQLAlchemy Model Base
Shared declarative base class for all ORM models.
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


from app.models.tenant import Tenant  # noqa: E402,F401
from app.models.user import User  # noqa: E402,F401
