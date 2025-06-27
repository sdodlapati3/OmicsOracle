"""
WebSocket service for real-time communication.

Provides WebSocket functionality for real-time updates, progress tracking,
and live search results.
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class WebSocketConnection:
    """Represents a WebSocket connection with metadata."""

    def __init__(self, websocket: WebSocket, connection_id: str):
        self.websocket = websocket
        self.connection_id = connection_id
        self.connected_at = datetime.now()
        self.last_activity = datetime.now()
        self.metadata: Dict[str, Any] = {}

    async def send_message(self, message: Dict[str, Any]) -> bool:
        """Send a message to the WebSocket client."""
        try:
            await self.websocket.send_text(json.dumps(message))
            self.last_activity = datetime.now()
            return True
        except Exception as e:
            logger.error(f"Failed to send message to {self.connection_id}: {e}")
            return False

    async def close(self, code: int = 1000, reason: str = "Normal closure"):
        """Close the WebSocket connection."""
        try:
            await self.websocket.close(code=code, reason=reason)
        except Exception as e:
            logger.error(f"Error closing connection {self.connection_id}: {e}")


class WebSocketService:
    """Service for managing WebSocket connections and broadcasting messages."""

    def __init__(self):
        self._connections: Dict[str, WebSocketConnection] = {}
        self._lock = asyncio.Lock()

    async def connect(
        self, websocket: WebSocket, connection_id: str
    ) -> WebSocketConnection:
        """Accept a new WebSocket connection."""
        await websocket.accept()

        connection = WebSocketConnection(websocket, connection_id)

        async with self._lock:
            self._connections[connection_id] = connection

        logger.info(f"WebSocket connected: {connection_id}")

        # Send welcome message
        await connection.send_message(
            {
                "type": "connection_established",
                "connection_id": connection_id,
                "timestamp": datetime.now().isoformat(),
            }
        )

        return connection

    async def disconnect(self, connection_id: str) -> None:
        """Disconnect a WebSocket connection."""
        async with self._lock:
            if connection_id in self._connections:
                connection = self._connections[connection_id]
                await connection.close()
                del self._connections[connection_id]
                logger.info(f"WebSocket disconnected: {connection_id}")

    async def send_to_connection(
        self, connection_id: str, message: Dict[str, Any]
    ) -> bool:
        """Send a message to a specific connection."""
        async with self._lock:
            connection = self._connections.get(connection_id)

        if connection:
            return await connection.send_message(message)

        logger.warning(f"Connection not found: {connection_id}")
        return False

    async def broadcast(
        self, message: Dict[str, Any], exclude: Optional[Set[str]] = None
    ) -> int:
        """Broadcast a message to all connected clients."""
        if exclude is None:
            exclude = set()

        success_count = 0
        failed_connections = []

        async with self._lock:
            connections = list(self._connections.items())

        for connection_id, connection in connections:
            if connection_id in exclude:
                continue

            success = await connection.send_message(message)
            if success:
                success_count += 1
            else:
                failed_connections.append(connection_id)

        # Clean up failed connections
        if failed_connections:
            async with self._lock:
                for connection_id in failed_connections:
                    if connection_id in self._connections:
                        del self._connections[connection_id]
                        logger.warning(
                            f"Removed failed connection: {connection_id}"
                        )

        logger.debug(f"Broadcast sent to {success_count} connections")
        return success_count

    async def send_search_progress(
        self, connection_id: str, progress: Dict[str, Any]
    ) -> bool:
        """Send search progress update to a specific connection."""
        message = {
            "type": "search_progress",
            "payload": progress,
            "timestamp": datetime.now().isoformat(),
        }
        return await self.send_to_connection(connection_id, message)

    async def send_search_results(
        self, connection_id: str, results: List[Dict[str, Any]]
    ) -> bool:
        """Send search results to a specific connection."""
        message = {
            "type": "search_results",
            "payload": {
                "results": results,
                "count": len(results),
            },
            "timestamp": datetime.now().isoformat(),
        }
        return await self.send_to_connection(connection_id, message)

    async def send_error(
        self, connection_id: str, error: str, error_type: str = "general"
    ) -> bool:
        """Send error message to a specific connection."""
        message = {
            "type": "error",
            "payload": {
                "error": error,
                "error_type": error_type,
            },
            "timestamp": datetime.now().isoformat(),
        }
        return await self.send_to_connection(connection_id, message)

    async def get_connection_count(self) -> int:
        """Get the number of active connections."""
        async with self._lock:
            return len(self._connections)

    async def get_connection_info(self) -> List[Dict[str, Any]]:
        """Get information about all active connections."""
        async with self._lock:
            info = []
            for connection_id, connection in self._connections.items():
                info.append(
                    {
                        "connection_id": connection_id,
                        "connected_at": connection.connected_at.isoformat(),
                        "last_activity": connection.last_activity.isoformat(),
                        "metadata": connection.metadata,
                    }
                )
            return info

    async def cleanup_stale_connections(
        self, max_idle_minutes: int = 30
    ) -> int:
        """Clean up connections that have been idle for too long."""
        cutoff_time = datetime.now().timestamp() - (max_idle_minutes * 60)
        stale_connections = []

        async with self._lock:
            for connection_id, connection in self._connections.items():
                if connection.last_activity.timestamp() < cutoff_time:
                    stale_connections.append(connection_id)

        for connection_id in stale_connections:
            await self.disconnect(connection_id)

        if stale_connections:
            logger.info(
                f"Cleaned up {len(stale_connections)} stale connections"
            )

        return len(stale_connections)
