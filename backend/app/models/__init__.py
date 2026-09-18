"""
SafeSOC — SQLAlchemy Model Base
Shared declarative base class for all ORM models.
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


from app.models.alert_annotation import AlertAnnotation  # noqa: E402,F401
from app.models.audit_log import AuditLog  # noqa: E402,F401
from app.models.endpoint import Endpoint  # noqa: E402,F401
from app.models.endpoint_software import EndpointSoftware  # noqa: E402,F401
from app.models.incident import Incident, IncidentNote, IncidentStateTransition  # noqa: E402,F401
from app.models.investigation_session import (  # noqa: E402,F401
    InvestigationAction,
    InvestigationFinding,
    InvestigationNote,
    InvestigationSession,
    InvestigationTurn,
)
from app.models.soar import SoarActionExecution, SoarPlaybookRun  # noqa: E402,F401
from app.models.tenant import Tenant  # noqa: E402,F401
from app.models.ti_cache import TICache  # noqa: E402,F401
from app.models.user import User  # noqa: E402,F401
