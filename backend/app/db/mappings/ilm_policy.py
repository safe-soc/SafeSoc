"""
SafeSOC — OpenSearch ISM (Index Lifecycle Management) Policy
Auto-deletes safesoc-alerts-* indices once they exceed the retention period.
"""

from app.core.config import settings

ILM_POLICY_ID = "safesoc-alerts-retention-policy"

ILM_POLICY = {
    "policy": {
        "description": "Deletes SafeSOC alert indices once they exceed the configured retention period.",
        "default_state": "hot",
        "states": [
            {
                "name": "hot",
                "actions": [],
                "transitions": [
                    {
                        "state_name": "delete",
                        "conditions": {
                            "min_index_age": f"{settings.OPENSEARCH_ILM_RETENTION_DAYS}d"
                        },
                    }
                ],
            },
            {
                "name": "delete",
                "actions": [{"delete": {}}],
                "transitions": [],
            },
        ],
        # New indices matching this pattern pick up the policy automatically
        # at creation time — no need to explicitly attach it per index.
        "ism_template": [
            {
                "index_patterns": ["safesoc-alerts-*"],
                "priority": 100,
            }
        ],
    }
}
