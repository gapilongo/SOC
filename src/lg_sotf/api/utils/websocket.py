"""WebSocket connection manager."""

import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, List

from fastapi import WebSocket


class WebSocketManager:
    """Manages WebSocket connections and message broadcasting."""

    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.client_subscriptions: Dict[str, List[str]] = {}
        self.heartbeat_task = None
        self.logger = logging.getLogger(__name__)

    async def connect(self, websocket: WebSocket, client_id: str):
        """Accept and register a new WebSocket connection."""
        await websocket.accept()
        self.active_connections[client_id] = websocket
        self.client_subscriptions[client_id] = []

        await self.send_personal_message({
            "type": "connection",
            "status": "connected",
            "client_id": client_id,
            "server_time": datetime.utcnow().isoformat()
        }, client_id)

    def disconnect(self, client_id: str):
        """Disconnect and unregister a WebSocket connection."""
        if client_id in self.active_connections:
            del self.active_connections[client_id]
        if client_id in self.client_subscriptions:
            del self.client_subscriptions[client_id]

    async def send_personal_message(self, message: dict, client_id: str):
        """Send a message to a specific client."""
        if client_id not in self.active_connections:
            return

        try:
            await self.active_connections[client_id].send_text(
                json.dumps(message, default=str)
            )
        except Exception as e:
            self.logger.warning(f"Failed to send to {client_id}: {e}")
            self.disconnect(client_id)

    async def broadcast(self, message: dict, subscription_type: str = None):
        """Broadcast a message to all connected clients."""
        disconnected = []

        for client_id, websocket in self.active_connections.items():
            if subscription_type:
                subscriptions = self.client_subscriptions.get(client_id, [])
                if subscription_type not in subscriptions:
                    continue

            try:
                await websocket.send_text(json.dumps(message, default=str))
            except Exception as e:
                self.logger.warning(f"Broadcast error to {client_id}: {e}")
                disconnected.append(client_id)

        for client_id in disconnected:
            self.disconnect(client_id)

    async def heartbeat_loop(self):
        """Send periodic heartbeat messages to all clients."""
        while True:
            try:
                await asyncio.sleep(30)

                message = {
                    "type": "heartbeat",
                    "timestamp": datetime.utcnow().isoformat(),
                    "active_connections": len(self.active_connections)
                }

                await self.broadcast(message)

            except asyncio.CancelledError:
                self.logger.info("Heartbeat loop cancelled")
                break
            except Exception as e:
                self.logger.error(f"Heartbeat error: {e}")
