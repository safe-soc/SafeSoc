"""
SafeSOC — Real-Time Dashboard WebSocket (SS-063)
GET (upgrade) /ws?token=<JWT> — pushes new-alert/chain-detected events
(published by services/realtime.py) to the connected tenant's
dashboard, so it updates live without polling.

Browsers' native WebSocket API can't set an Authorization header, so
the JWT travels as a query parameter instead — decoded with the exact
same core/security.decode_access_token() every other authenticated
route uses, closed with policy violation (1008) if missing/invalid,
matching get_current_user's 401 behavior as closely as a WebSocket
close code allows.
"""

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.exceptions import InvalidTokenError
from app.core.security import decode_access_token
from app.db.redis import get_client
from app.services.realtime import channel_name
from app.utils.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(tags=["realtime"])


async def _forward_events(websocket: WebSocket, pubsub) -> None:
    """
    Relay every message published to this tenant's Redis channel out
    over the socket. db/redis.py's client has no decode_responses=True,
    so pubsub payloads arrive as bytes — Starlette's send_text() needs
    a str, not bytes (confirmed live: an unmocked run raised
    AttributeError: 'bytes' object has no attribute 'encode' here).
    """
    while True:
        message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
        if message is not None:
            data = message["data"]
            await websocket.send_text(data.decode("utf-8") if isinstance(data, bytes) else data)


async def _watch_for_disconnect(websocket: WebSocket) -> None:
    """
    The forwarding loop above only ever sends — nothing about it would
    ever notice the client going away. Actively awaiting receive() is
    what actually raises WebSocketDisconnect, so a dead connection's
    Redis subscription gets cleaned up promptly instead of leaking
    until the next failed send.
    """
    while True:
        await websocket.receive_text()


@router.websocket("/ws")
async def dashboard_events(websocket: WebSocket) -> None:
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=1008)
        return

    try:
        claims = decode_access_token(token)
    except InvalidTokenError:
        await websocket.close(code=1008)
        return

    tenant_id = claims["tenant_id"]
    await websocket.accept()

    client = get_client()
    pubsub = client.pubsub()
    await pubsub.subscribe(channel_name(tenant_id))

    forward_task = asyncio.create_task(_forward_events(websocket, pubsub))
    disconnect_task = asyncio.create_task(_watch_for_disconnect(websocket))

    try:
        done, pending = await asyncio.wait({forward_task, disconnect_task}, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        for task in done:
            exc = task.exception()
            if exc is not None and not isinstance(exc, WebSocketDisconnect):
                raise exc
    except WebSocketDisconnect:
        pass
    finally:
        await pubsub.unsubscribe(channel_name(tenant_id))
        await pubsub.close()
