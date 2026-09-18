"""
SafeSOC — Simulated Email Gateway Adapter
Scaffolded per the Phase 2 architecture's "at minimum" adapter set. No
current SoarActionType is routed to this adapter — none of Phase 1's
10 action types represents an email-gateway action (block/isolate/
disable/revoke/terminate all target an endpoint, account, or network
indicator; the two "automatic" note/evidence/enrich/investigation-
action types are internal SafeSOC operations, not an external-system
boundary). This class exists, satisfies the SoarActionAdapter contract,
and is exercised directly by tests, but adapters/soar/__init__.py does
not register it against any action type — there is nothing to route to
it yet. It's the natural handler for a future action type such as
"notify stakeholders via email," should one be added.

As with every adapter in this package: no real email is ever sent by
this module — every result modifies nothing outside SafeSOC's own
synthetic demo state, and every message is explicitly labeled
[SIMULATED].
"""

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.soar.sdk import SoarActionResult, SoarVerificationResult
from app.core.enums import SoarActionType


class SimulatedEmailGateway:
    name = "simulated_email"

    async def execute(
        self, db: AsyncSession, tenant_id: uuid.UUID, action_type: SoarActionType, parameters: dict
    ) -> SoarActionResult:
        recipient = parameters.get("recipient") or "soc-team@safesoc.internal"
        return SoarActionResult(
            success=True, adapter=self.name, action=action_type.value, target=recipient,
            message=(
                f"[SIMULATED] Simulated email gateway recorded a notification to '{recipient}' in SafeSOC's "
                "synthetic demo environment. No real email was sent."
            ),
            state_change={"recipient": recipient, "status": "queued"},
        )

    async def verify(
        self, db: AsyncSession, tenant_id: uuid.UUID, action_type: SoarActionType, result: SoarActionResult
    ) -> SoarVerificationResult:
        if not result.success:
            return SoarVerificationResult(verified=False, message="Cannot verify a failed execution result.")
        if result.state_change.get("status") == "queued":
            return SoarVerificationResult(verified=True, message=f"[SIMULATED] Confirmed synthetic email queue contains a notification to '{result.target}'.")
        return SoarVerificationResult(verified=False, message="Simulated email gateway state does not reflect the expected change — verification failed.")
