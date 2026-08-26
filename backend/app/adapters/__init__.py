"""
SafeSOC — Source Adapters
Transforms for each supported log source's raw, native payload shape
into NormalizedLog-shaped fields. See adapters/sdk.py for the formal
LogAdapter contract (SS-069) both these built-ins and any third-party
adapter implement, and for the shared `registry` they register
against — importing this package registers all four below.
"""

from app.adapters import cloudlens, cloudtrail, guardduty, wazuh
from app.adapters.sdk import registry
from app.core.enums import LogSource

registry.register(LogSource.WAZUH.value, wazuh.transform)
registry.register(LogSource.AWS_CLOUDTRAIL.value, cloudtrail.transform)
registry.register(LogSource.AWS_GUARDDUTY.value, guardduty.transform)
registry.register(LogSource.CLOUDLENS.value, cloudlens.transform)

__all__ = ["cloudlens", "cloudtrail", "guardduty", "wazuh", "registry"]
