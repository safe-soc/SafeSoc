"""
SafeSOC — Simulated Firewall Adapter
Handles BLOCK_INDICATOR. There is no real firewall, network device,
or blocklist distribution anywhere in this module — every result
describes a change to SafeSOC's own synthetic demo state only, and
every message is explicitly labeled [SIMULATED]. The indicator was
already validated as a syntactically real IP or domain, with dangerous
characters rejected, at action-creation time
(app/schemas/soar.py::BlockIndicatorParams) — this adapter never
re-parses or re-validates it, just acts on the already-trusted value.
"""

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.soar.sdk import SoarActionResult, SoarVerificationResult
from app.core.enums import SoarActionType


class SimulatedFirewall:
    name = "simulated_firewall"

    async def execute(
        self, db: AsyncSession, tenant_id: uuid.UUID, action_type: SoarActionType, parameters: dict
    ) -> SoarActionResult:
        indicator = parameters.get("indicator")

        if action_type != SoarActionType.BLOCK_INDICATOR:
            return SoarActionResult(
                success=False, adapter=self.name, action=action_type.value, target=indicator or "unknown",
                message=f"Simulated firewall does not handle action type '{action_type.value}'.",
            )
        if not indicator:
            return SoarActionResult(
                success=False, adapter=self.name, action=action_type.value, target="unknown",
                message="[SIMULATED] No target indicator was supplied — nothing to block.",
            )

        return SoarActionResult(
            success=True, adapter=self.name, action=action_type.value, target=indicator,
            message=(
                f"[SIMULATED] Simulated firewall recorded indicator '{indicator}' as blocked in SafeSOC's "
                "synthetic demo environment. No real firewall, network device, or traffic was affected."
            ),
            state_change={"indicator": indicator, "status": "blocked"},
        )

    async def verify(
        self, db: AsyncSession, tenant_id: uuid.UUID, action_type: SoarActionType, result: SoarActionResult
    ) -> SoarVerificationResult:
        if not result.success:
            return SoarVerificationResult(verified=False, message="Cannot verify a failed execution result.")

        if result.state_change.get("status") == "blocked" and result.state_change.get("indicator") == result.target:
            return SoarVerificationResult(
                verified=True, message=f"[SIMULATED] Confirmed synthetic firewall blocklist contains '{result.target}'.",
            )
        return SoarVerificationResult(
            verified=False, message="Simulated firewall state does not reflect the expected block — verification failed."
        )
