"""
SafeSOC — SOAR Action Adapter SDK
Formalizes the boundary between the SOAR dispatcher (services/
soar_execution.py) and every "simulated integration" that actually
carries out an APPROVAL_REQUIRED action — mirrors adapters/sdk.py's
LogAdapter Protocol + AdapterRegistry pattern exactly, one level up
(action execution instead of log ingestion).

Contract every adapter — built-in or, in principle, a future one —
must satisfy:

- execute()/verify() return STRUCTURED SoarActionResult/
  SoarVerificationResult values only — never a raw string, never
  something requiring further interpretation by the caller. This is
  the same "typed, closed shape" discipline the MCP tool boundary
  (app/mcp/tools.py) already applies to what the AI can call.
- Neither method may run a shell command, a SQL statement, arbitrary
  Python, an arbitrary HTTP request, or spawn a subprocess. An
  adapter's database access (if any) is the ordinary SQLAlchemy ORM
  session every other service in this codebase already uses — never a
  raw query string built from action parameters.
- MUST NOT raise for a well-formed action. A failure is reported via
  `success=False` / `verified=False`, never an exception — so the
  dispatcher's own state machine (services/soar.py, Phase 1, UNCHANGED
  here) is what a failure flows through, consistent with parameters
  already having been validated at action-creation time
  (app/schemas/soar.py) before this is ever called.
- Every built-in adapter under app/adapters/soar/ modifies ONLY
  SafeSOC's own synthetic/demo state (there is no real EDR, identity
  provider, firewall, or email gateway anywhere in this codebase) and
  says so explicitly in every message it returns.
"""

import uuid
from dataclasses import dataclass, field
from typing import Optional, Protocol, runtime_checkable

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import SoarActionType

SOAR_ADAPTER_SDK_VERSION = "1.0.0"


@dataclass(frozen=True)
class SoarActionResult:
    """The ONLY shape an adapter's execute() may return — see SoarActionAdapter's contract above."""
    success: bool
    adapter: str
    action: str
    target: str
    message: str
    state_change: dict = field(default_factory=dict)


@dataclass(frozen=True)
class SoarVerificationResult:
    """The ONLY shape an adapter's verify() may return."""
    verified: bool
    message: str


@runtime_checkable
class SoarActionAdapter(Protocol):
    """
    One simulated (or, structurally, a future real) integration a SOAR
    action executes against. `name` is the adapter's own identifier,
    echoed into every SoarActionResult it produces (e.g.
    "simulated_edr") so a result is self-describing without the caller
    needing to already know which adapter handled it.
    """

    name: str

    async def execute(
        self, db: AsyncSession, tenant_id: uuid.UUID, action_type: SoarActionType, parameters: dict
    ) -> SoarActionResult: ...

    async def verify(
        self, db: AsyncSession, tenant_id: uuid.UUID, action_type: SoarActionType, result: SoarActionResult
    ) -> SoarVerificationResult: ...


class SoarAdapterRegistry:
    """
    Maps a SoarActionType to the adapter that handles it. Mirrors
    adapters/sdk.py's AdapterRegistry: a small class rather than a
    plain dict literal, so registering a new action type is one
    documented call, and an accidental double-registration is caught
    rather than silently overwriting an existing adapter.
    """

    def __init__(self) -> None:
        self._adapters: dict[SoarActionType, SoarActionAdapter] = {}

    def register(self, action_type: SoarActionType, adapter: SoarActionAdapter, *, replace: bool = False) -> None:
        """
        Raises:
            TypeError: if `adapter` doesn't satisfy the SoarActionAdapter
            contract (the structural parts runtime_checkable can verify —
            it has `name`, `execute`, and `verify`).
            ValueError: if `action_type` is already registered and
            `replace` isn't explicitly set.
        """
        if not isinstance(adapter, SoarActionAdapter):
            raise TypeError(f"Adapter for action type '{action_type.value}' must implement SoarActionAdapter.")
        if action_type in self._adapters and not replace:
            raise ValueError(
                f"An adapter is already registered for SOAR action type '{action_type.value}'. "
                "Pass replace=True if you intend to override it."
            )
        self._adapters[action_type] = adapter

    def get(self, action_type: SoarActionType) -> Optional[SoarActionAdapter]:
        return self._adapters.get(action_type)

    def action_types(self) -> list[SoarActionType]:
        return list(self._adapters)


# One shared registry for the running application — built-in adapters
# register themselves against this in adapters/soar/__init__.py;
# importing that package registers everything.
registry = SoarAdapterRegistry()
