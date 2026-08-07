"""
SafeSOC — Real-Time Dashboard WebSocket Tests (SS-063)
Auth rejection is tested through a real WebSocket handshake via
TestClient. The forwarding loop itself is tested as a plain unit
(fake websocket + fake pubsub) rather than through a full handshake —
asyncio.wait()'ing two long-running tasks against TestClient's sync/
async bridge is exactly the kind of fragile, timing-dependent harness
this project has avoided elsewhere (see test_investigate_router.py's
own docstring on the same TestClient portal behavior). Full push
behavior is verified live against a real Redis + running server (see
the batch report).
"""

import asyncio
import uuid
from unittest.mock import AsyncMock

import pytest
from starlette.websockets import WebSocketDisconnect

from app.core.enums import UserRole
from app.core.security import create_access_token
from app.routers import ws as ws_router


def test_dashboard_events_rejects_a_connection_with_no_token(client):
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws"):
            pass


def test_dashboard_events_rejects_a_connection_with_an_invalid_token(client):
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws?token=not-a-real-jwt"):
            pass


def test_dashboard_events_accepts_a_connection_with_a_valid_token(client, monkeypatch):
    class _FakePubSub:
        async def subscribe(self, channel):
            pass

        async def get_message(self, ignore_subscribe_messages=True, timeout=1.0):
            # A real redis-py get_message() performs actual async I/O, which
            # yields control to the event loop — this fake must do the same
            # (asyncio.sleep(0)) or it starves the sibling disconnect-watching
            # task in a tight loop, and the test hangs forever.
            await asyncio.sleep(0)
            return None

        async def unsubscribe(self, channel):
            pass

        async def close(self):
            pass

    class _FakeRedisClient:
        def pubsub(self):
            return _FakePubSub()

    monkeypatch.setattr(ws_router, "get_client", lambda: _FakeRedisClient())

    token = create_access_token(uuid.uuid4(), uuid.uuid4(), UserRole.ANALYST)
    with client.websocket_connect(f"/ws?token={token}") as websocket:
        # A successful accept() is the assertion — closing cleanly (not a
        # 1008 policy-violation rejection) proves the token was accepted.
        websocket.close()


@pytest.mark.asyncio
async def test_forward_events_relays_a_published_message_over_the_socket():
    """
    Regression test: db/redis.py's client has no decode_responses=True,
    so a real pubsub payload arrives as bytes, not str — this fake
    matches that (caught live: an earlier version of _forward_events
    passed bytes straight to send_text(), which requires a str, and
    raised AttributeError on every single push).
    """
    websocket = AsyncMock()

    class _FakePubSub:
        def __init__(self):
            self._messages = [{"type": "message", "data": b'{"type": "new_alert"}'}]

        async def get_message(self, ignore_subscribe_messages=True, timeout=1.0):
            if self._messages:
                return self._messages.pop(0)
            raise StopAsyncIteration  # stop the test's forward loop after one message

    with pytest.raises(StopAsyncIteration):
        await ws_router._forward_events(websocket, _FakePubSub())

    websocket.send_text.assert_called_once_with('{"type": "new_alert"}')


@pytest.mark.asyncio
async def test_forward_events_ignores_ticks_with_no_message():
    websocket = AsyncMock()
    call_count = 0

    class _FakePubSub:
        async def get_message(self, ignore_subscribe_messages=True, timeout=1.0):
            nonlocal call_count
            call_count += 1
            if call_count >= 3:
                raise StopAsyncIteration
            return None

    with pytest.raises(StopAsyncIteration):
        await ws_router._forward_events(websocket, _FakePubSub())

    websocket.send_text.assert_not_called()
