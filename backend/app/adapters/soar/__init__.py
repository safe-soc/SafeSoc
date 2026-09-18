"""
SafeSOC — SOAR Simulated Integrations
Simulated adapters for every APPROVAL_REQUIRED SoarActionType (core/
soar_policy.py) — see adapters/soar/sdk.py for the formal
SoarActionAdapter contract these implement and the shared `registry`
they register against. Importing this package registers all four.

None of these adapters connects to a real EDR, identity provider,
firewall, email gateway, or any other external/production system —
every one modifies only SafeSOC's own synthetic/demo state. See each
module's own docstring for details.
"""

from app.adapters.soar import simulated_edr, simulated_email, simulated_firewall, simulated_identity
from app.adapters.soar.sdk import registry
from app.core.enums import SoarActionType

_edr = simulated_edr.SimulatedEDR()
_identity = simulated_identity.SimulatedIdentityProvider()
_firewall = simulated_firewall.SimulatedFirewall()
# simulated_email.SimulatedEmailGateway is intentionally NOT registered
# against any action type yet — see its own module docstring.

registry.register(SoarActionType.ISOLATE_ENDPOINT, _edr)
registry.register(SoarActionType.TERMINATE_PROCESS, _edr)
registry.register(SoarActionType.DISABLE_ACCOUNT, _identity)
registry.register(SoarActionType.REVOKE_CREDENTIALS, _identity)
registry.register(SoarActionType.BLOCK_INDICATOR, _firewall)

__all__ = ["simulated_edr", "simulated_email", "simulated_firewall", "simulated_identity", "registry"]
