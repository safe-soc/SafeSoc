"""
SafeSOC — Simulated EDR Adapter
Handles ISOLATE_ENDPOINT and TERMINATE_PROCESS. There is no real EDR
integration anywhere in this module — every result modifies nothing
outside this call's own return value, and every message is explicitly
labeled [SIMULATED]. "Verifying" an isolation/termination means
re-checking the adapter's own just-returned result for internal
consistency (there is no live external system to poll); a target
host_id that isn't a known Endpoint for this tenant is treated as a
genuine, deterministic execution failure — the honest simulated
analogue of "the EDR agent isn't installed on that host."
"""

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.soar.sdk import SoarActionResult, SoarVerificationResult
from app.core.enums import SoarActionType
from app.services.risk_scoring import get_endpoint

_HANDLED_ACTIONS = frozenset({SoarActionType.ISOLATE_ENDPOINT, SoarActionType.TERMINATE_PROCESS})
_EXPECTED_STATUS = {
    SoarActionType.ISOLATE_ENDPOINT: "isolated",
    SoarActionType.TERMINATE_PROCESS: "terminated",
}


class SimulatedEDR:
    name = "simulated_edr"

    async def execute(
        self, db: AsyncSession, tenant_id: uuid.UUID, action_type: SoarActionType, parameters: dict
    ) -> SoarActionResult:
        host_id = parameters.get("host_id")

        if action_type not in _HANDLED_ACTIONS:
            return SoarActionResult(
                success=False, adapter=self.name, action=action_type.value, target=host_id or "unknown",
                message=f"Simulated EDR does not handle action type '{action_type.value}'.",
            )

        endpoint = await get_endpoint(db, tenant_id, host_id) if host_id else None
        if endpoint is None:
            return SoarActionResult(
                success=False, adapter=self.name, action=action_type.value, target=host_id or "unknown",
                message=f"[SIMULATED] Simulated EDR has no record of host '{host_id}' — cannot act on an unknown endpoint.",
            )

        if action_type == SoarActionType.ISOLATE_ENDPOINT:
            return SoarActionResult(
                success=True, adapter=self.name, action=action_type.value, target=host_id,
                message=(
                    f"[SIMULATED] Endpoint '{host_id}' marked isolated in SafeSOC's synthetic demo environment. "
                    "No real endpoint, network, or production system was affected."
                ),
                state_change={"host_id": host_id, "status": "isolated"},
            )

        process = parameters.get("process") or "unknown process"
        return SoarActionResult(
            success=True, adapter=self.name, action=action_type.value, target=host_id,
            message=(
                f"[SIMULATED] Process '{process}' marked terminated on host '{host_id}' in SafeSOC's synthetic "
                "demo environment. No real process was affected."
            ),
            state_change={"host_id": host_id, "process": process, "status": "terminated"},
        )

    async def verify(
        self, db: AsyncSession, tenant_id: uuid.UUID, action_type: SoarActionType, result: SoarActionResult
    ) -> SoarVerificationResult:
        if not result.success:
            return SoarVerificationResult(verified=False, message="Cannot verify a failed execution result.")

        expected_status = _EXPECTED_STATUS.get(action_type)
        if expected_status is not None and result.state_change.get("status") == expected_status:
            return SoarVerificationResult(
                verified=True,
                message=f"[SIMULATED] Confirmed synthetic EDR state shows '{expected_status}' for '{result.target}'.",
            )
        return SoarVerificationResult(
            verified=False, message="Simulated EDR state does not reflect the expected change — verification failed."
        )
