"""
SafeSOC — Simulated Identity Provider Adapter
Handles DISABLE_ACCOUNT and REVOKE_CREDENTIALS. There is no real
identity provider integration anywhere in this module. The `user`
target is a raw username string observed in alert/evidence data
(services/incident_evidence.py's UserEntity) — SafeSOC's own `users`
table models platform login accounts (analysts/admins/viewers), a
completely different concept, and is never consulted or touched here.
Every message is explicitly labeled [SIMULATED].

Unlike SimulatedEDR, there is no existing "known accounts" table to
check a target against, so execute() succeeds for any non-empty
username — the parameter was already validated as non-empty at
action-creation time (app/schemas/soar.py). verify() re-checks the
adapter's own returned result for internal consistency.
"""

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.soar.sdk import SoarActionResult, SoarVerificationResult
from app.core.enums import SoarActionType

_HANDLED_ACTIONS = frozenset({SoarActionType.DISABLE_ACCOUNT, SoarActionType.REVOKE_CREDENTIALS})
_EXPECTED_STATUS = {
    SoarActionType.DISABLE_ACCOUNT: "disabled",
    SoarActionType.REVOKE_CREDENTIALS: "credentials_revoked",
}


class SimulatedIdentityProvider:
    name = "simulated_identity"

    async def execute(
        self, db: AsyncSession, tenant_id: uuid.UUID, action_type: SoarActionType, parameters: dict
    ) -> SoarActionResult:
        user = parameters.get("user")

        if action_type not in _HANDLED_ACTIONS:
            return SoarActionResult(
                success=False, adapter=self.name, action=action_type.value, target=user or "unknown",
                message=f"Simulated identity provider does not handle action type '{action_type.value}'.",
            )
        if not user:
            return SoarActionResult(
                success=False, adapter=self.name, action=action_type.value, target="unknown",
                message="[SIMULATED] No target account was supplied — nothing to act on.",
            )

        status = _EXPECTED_STATUS[action_type]
        verb = "disabled" if action_type == SoarActionType.DISABLE_ACCOUNT else "revoked credentials for"
        return SoarActionResult(
            success=True, adapter=self.name, action=action_type.value, target=user,
            message=(
                f"[SIMULATED] Simulated identity provider {verb} account '{user}' in SafeSOC's synthetic demo "
                "environment. No real identity provider, directory, or user account was affected."
            ),
            state_change={"user": user, "status": status},
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
                message=f"[SIMULATED] Confirmed synthetic identity provider state shows '{expected_status}' for '{result.target}'.",
            )
        return SoarVerificationResult(
            verified=False, message="Simulated identity provider state does not reflect the expected change — verification failed."
        )
