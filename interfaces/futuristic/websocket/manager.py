"""
WebSocket manager for real-time communication
"""

import asyncio
from datetime import datetime
from typing import List

from core.config import EnhancedConfig
from fastapi import APIRouter, WebSocket, WebSocketDisconnect


# Connection manager
class ConnectionManager:
    """Manages WebSocket connections"""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        """Connect a new WebSocket"""
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        """Disconnect a WebSocket"""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def send_personal_message(self, message: dict, websocket: WebSocket):
        """Send message to specific WebSocket"""
        try:
            await websocket.send_json(message)
        except:
            self.disconnect(websocket)

    async def broadcast(self, message: dict):
        """Broadcast message to all connected WebSockets"""
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                disconnected.append(connection)

        # Remove disconnected clients
        for connection in disconnected:
            self.disconnect(connection)


# Global connection manager instance
manager = ConnectionManager()


def create_websocket_router(config: EnhancedConfig) -> APIRouter:
    """Create WebSocket router"""

    router = APIRouter()

    @router.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket):
        """WebSocket endpoint for real-time communication"""
        await manager.connect(websocket)

        try:
            # Send welcome message
            await manager.send_personal_message(
                {
                    "type": "connection",
                    "message": "Connected to Enhanced OmicsOracle Interface",
                    "timestamp": datetime.now().isoformat(),
                },
                websocket,
            )

            # Keep connection alive with periodic updates
            while True:
                await asyncio.sleep(config.websocket_heartbeat_interval)

                await manager.send_personal_message(
                    {
                        "type": "heartbeat",
                        "status": "System operational",
                        "active_connections": len(manager.active_connections),
                        "timestamp": datetime.now().isoformat(),
                    },
                    websocket,
                )

        except WebSocketDisconnect:
            manager.disconnect(websocket)
        except Exception as e:
            print(f"WebSocket error: {e}")
            manager.disconnect(websocket)

    return router


async def notify_all_connections(message: str):
    """Helper function to send notifications to all connections"""
    await manager.broadcast(
        {
            "type": "notification",
            "message": message,
            "timestamp": datetime.now().isoformat(),
        }
    )
