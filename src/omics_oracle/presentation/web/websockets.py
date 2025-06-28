"""
WebSocket endpoints for real-time communication.

This module provides WebSocket endpoints for the futuristic interface,
enabling real-time updates, live search progress, and interactive features.
"""

import asyncio
import json
import logging
import time
from typing import Dict, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages WebSocket connections for real-time communication."""

    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.client_data: Dict[str, Dict] = {}

    async def connect(self, websocket: WebSocket, client_id: str):
        """Accept a new WebSocket connection."""
        await websocket.accept()
        self.active_connections[client_id] = websocket
        self.client_data[client_id] = {
            "connected_at": time.time(),
            "last_activity": time.time(),
        }
        logger.info(f"Client {client_id} connected. Total connections: {len(self.active_connections)}")

    def disconnect(self, client_id: str):
        """Remove a WebSocket connection."""
        if client_id in self.active_connections:
            del self.active_connections[client_id]
        if client_id in self.client_data:
            del self.client_data[client_id]
        logger.info(f"Client {client_id} disconnected. Total connections: {len(self.active_connections)}")

    async def send_personal_message(self, message: dict, client_id: str):
        """Send a message to a specific client."""
        if client_id in self.active_connections:
            try:
                websocket = self.active_connections[client_id]
                await websocket.send_text(json.dumps(message))
                self.client_data[client_id]["last_activity"] = time.time()
            except Exception as e:
                logger.error(f"Error sending message to {client_id}: {e}")
                self.disconnect(client_id)

    async def broadcast(self, message: dict):
        """Send a message to all connected clients."""
        for client_id in list(self.active_connections.keys()):
            await self.send_personal_message(message, client_id)

    async def send_search_progress(
        self, client_id: str, progress: int, status: str, details: Optional[str] = None
    ):
        """Send search progress update to a specific client."""
        message = {
            "type": "search_progress",
            "progress": progress,
            "status": status,
            "details": details,
            "timestamp": time.time(),
        }
        await self.send_personal_message(message, client_id)

    async def send_search_results(self, client_id: str, results: dict):
        """Send search results to a specific client."""
        message = {"type": "search_results", "data": results, "timestamp": time.time()}
        await self.send_personal_message(message, client_id)

    async def send_system_status(self, client_id: str, status: dict):
        """Send system status update to a specific client."""
        message = {"type": "system_status", "data": status, "timestamp": time.time()}
        await self.send_personal_message(message, client_id)


# Global connection manager instance
manager = ConnectionManager()


def setup_websockets(app: FastAPI) -> None:
    """Setup WebSocket endpoints for real-time communication."""

    @app.websocket("/ws/{client_id}")
    async def websocket_endpoint(websocket: WebSocket, client_id: str):
        """WebSocket endpoint for real-time communication."""
        await manager.connect(websocket, client_id)

        # Send initial connection confirmation
        await manager.send_personal_message(
            {
                "type": "connection_established",
                "client_id": client_id,
                "timestamp": time.time(),
                "message": "Connected to OmicsOracle Futuristic Interface",
            },
            client_id,
        )

        try:
            while True:
                # Receive messages from client
                data = await websocket.receive_text()
                try:
                    message = json.loads(data)
                    await handle_client_message(client_id, message)
                except json.JSONDecodeError:
                    logger.error(f"Invalid JSON received from {client_id}: {data}")
                    await manager.send_personal_message(
                        {"type": "error", "message": "Invalid JSON format"}, client_id
                    )

        except WebSocketDisconnect:
            manager.disconnect(client_id)
        except Exception as e:
            logger.error(f"WebSocket error for {client_id}: {e}")
            manager.disconnect(client_id)

    @app.websocket("/ws/system/monitor")
    async def system_monitor_websocket(websocket: WebSocket):
        """WebSocket endpoint for system monitoring."""
        await websocket.accept()
        try:
            while True:
                # Send system metrics every 5 seconds
                status = {
                    "connected_clients": len(manager.active_connections),
                    "server_time": time.time(),
                    "status": "operational",
                }
                await websocket.send_text(
                    json.dumps({"type": "system_metrics", "data": status, "timestamp": time.time()})
                )
                await asyncio.sleep(5)
        except WebSocketDisconnect:
            pass

    logger.info("WebSocket endpoints configured successfully")


async def handle_client_message(client_id: str, message: dict):
    """Handle incoming messages from WebSocket clients."""
    message_type = message.get("type")

    if message_type == "ping":
        await manager.send_personal_message({"type": "pong", "timestamp": time.time()}, client_id)

    elif message_type == "search_request":
        # Handle search requests through WebSocket
        query = message.get("query", "")
        await manager.send_search_progress(client_id, 10, "Initializing search...", f"Query: {query}")

        # Simulate search progress (in real implementation, this would be integrated with actual search)
        for progress in [25, 50, 75, 90]:
            await asyncio.sleep(0.5)
            await manager.send_search_progress(client_id, progress, f"Processing... {progress}%")

        await manager.send_search_progress(client_id, 100, "Search completed!")

    elif message_type == "get_system_status":
        status = {
            "version": "3.0.0-futuristic",
            "uptime": time.time() - 1672531200,  # Placeholder
            "active_connections": len(manager.active_connections),
            "features": ["real-time-search", "websockets", "ai-agents", "visualization"],
        }
        await manager.send_system_status(client_id, status)

    else:
        logger.warning(f"Unknown message type from {client_id}: {message_type}")


# Export the manager for use in other modules
__all__ = ["setup_websockets", "manager"]
