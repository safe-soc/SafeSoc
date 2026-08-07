"""
SafeSOC — Real-Time Event Publishing Tests (SS-063)
"""

import json
from unittest.mock import AsyncMock

import pytest

from app.services import realtime


def test_channel_name_is_namespaced_per_tenant():
    assert realtime.channel_name("acme-corp") == "realtime:acme-corp"
    assert realtime.channel_name("acme-corp") != realtime.channel_name("globex-inc")


@pytest.mark.asyncio
async def test_publish_event_publishes_to_the_tenants_channel(monkeypatch):
    mock_client = AsyncMock()
    monkeypatch.setattr(realtime, "get_client", lambda: mock_client)

    await realtime.publish_event("acme-corp", "new_alert", {"alert_id": "a1", "host_id": "DESKTOP-042"})

    mock_client.publish.assert_called_once()
    channel, message = mock_client.publish.call_args.args
    assert channel == "realtime:acme-corp"
    assert json.loads(message) == {"type": "new_alert", "alert_id": "a1", "host_id": "DESKTOP-042"}
