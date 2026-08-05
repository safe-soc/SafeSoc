"""
SafeSOC — SQLAlchemy Model Base
Shared declarative base class for all ORM models.
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass
