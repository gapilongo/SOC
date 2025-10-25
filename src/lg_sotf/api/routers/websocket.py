"""WebSocket endpoint for real-time updates."""

import json
import logging
from datetime import datetime

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/{client_id}")
async def websocket_endpoint(
    websocket: WebSocket,
    client_id: str
):
    """WebSocket endpoint for real-time updates."""
    # Get WebSocket manager from app state
    ws_manager = websocket.app.state.ws_manager

    await ws_manager.connect(websocket, client_id)

    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)

            if message.get("type") == "subscribe":
                subscriptions = message.get("subscriptions", [])
                ws_manager.client_subscriptions[client_id] = subscriptions

                await ws_manager.send_personal_message({
                    "type": "subscription_confirmed",
                    "subscriptions": subscriptions
                }, client_id)

            elif message.get("type") == "ping":
                await ws_manager.send_personal_message({
                    "type": "pong",
                    "timestamp": datetime.utcnow().isoformat()
                }, client_id)

    except WebSocketDisconnect:
        ws_manager.disconnect(client_id)
        logger.info(f"Client {client_id} disconnected")
