"""
WebSocket Manager for Futuristic Interface

Manages real-time WebSocket connections and message broadcasting
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, Set

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class WebSocketManager:
    """Manages WebSocket connections for real-time updates"""

    def __init__(self):
        # Store active connections by client_id
        self.active_connections: Dict[str, Set[WebSocket]] = {}
        self.connection_metadata: Dict[str, Dict[str, Any]] = {}

    async def connect(self, websocket: WebSocket, client_id: str) -> None:
        """Accept a new WebSocket connection"""
        await websocket.accept()

        # Initialize client connections if not exists
        if client_id not in self.active_connections:
            self.active_connections[client_id] = set()
            self.connection_metadata[client_id] = {
                "connected_at": datetime.utcnow(),
                "message_count": 0,
                "last_activity": datetime.utcnow(),
            }

        # Add this connection to the client's set
        self.active_connections[client_id].add(websocket)

        logger.info(f"[CONNECT] WebSocket connected: {client_id}")

        # Send welcome message
        await self.send_personal_message(
            {
                "type": "connection_established",
                "client_id": client_id,
                "message": "Connected to OmicsOracle Futuristic Interface",
                "timestamp": datetime.utcnow().isoformat(),
                "capabilities": [
                    "real_time_search",
                    "live_analysis",
                    "interactive_visualization",
                    "agent_communication",
                ],
            },
            client_id,
        )

    async def disconnect(self, websocket: WebSocket, client_id: str) -> None:
        """Remove a WebSocket connection"""
        if client_id in self.active_connections:
            self.active_connections[client_id].discard(websocket)

            # If no more connections for this client, clean up metadata
            if not self.active_connections[client_id]:
                del self.active_connections[client_id]
                if client_id in self.connection_metadata:
                    del self.connection_metadata[client_id]

        logger.info(f"[CONNECT] WebSocket disconnected: {client_id}")

    async def send_personal_message(self, message: Dict[str, Any], client_id: str) -> bool:
        """Send message to a specific client"""
        if client_id not in self.active_connections:
            logger.warning(f"[WARNING] Client {client_id} not connected")
            return False

        # Update activity metadata
        if client_id in self.connection_metadata:
            self.connection_metadata[client_id]["last_activity"] = datetime.utcnow()
            self.connection_metadata[client_id]["message_count"] += 1

        # Send to all connections for this client
        successful_sends = 0
        failed_connections = []

        for connection in self.active_connections[client_id].copy():
            try:
                await connection.send_text(json.dumps(message, default=str))
                successful_sends += 1
            except Exception as e:
                logger.error(f"[ERROR] Failed to send message to {client_id}: {e}")
                failed_connections.append(connection)

        # Clean up failed connections
        for failed_conn in failed_connections:
            self.active_connections[client_id].discard(failed_conn)

        return successful_sends > 0

    async def broadcast_message(self, message: Dict[str, Any]) -> int:
        """Broadcast message to all connected clients"""
        sent_count = 0

        for client_id in list(self.active_connections.keys()):
            if await self.send_personal_message(message, client_id):
                sent_count += 1

        logger.info(f"[BROADCAST] Broadcast message sent to {sent_count} clients")
        return sent_count

    async def send_to_multiple_clients(self, message: Dict[str, Any], client_ids: list) -> int:
        """Send message to multiple specific clients"""
        sent_count = 0

        for client_id in client_ids:
            if await self.send_personal_message(message, client_id):
                sent_count += 1

        return sent_count

    async def get_connection_stats(self) -> Dict[str, Any]:
        """Get connection statistics"""
        total_connections = sum(len(connections) for connections in self.active_connections.values())

        stats = {
            "total_clients": len(self.active_connections),
            "total_connections": total_connections,
            "clients": {},
        }

        for client_id, metadata in self.connection_metadata.items():
            stats["clients"][client_id] = {
                "connection_count": len(self.active_connections.get(client_id, [])),
                "connected_at": metadata["connected_at"].isoformat(),
                "last_activity": metadata["last_activity"].isoformat(),
                "message_count": metadata["message_count"],
            }

        return stats

    async def cleanup_inactive_connections(self, timeout_minutes: int = 30) -> int:
        """Clean up connections that have been inactive for too long"""
        cutoff_time = datetime.utcnow().timestamp() - (timeout_minutes * 60)
        cleaned_count = 0

        for client_id in list(self.active_connections.keys()):
            if client_id in self.connection_metadata:
                last_activity = self.connection_metadata[client_id]["last_activity"]
                if last_activity.timestamp() < cutoff_time:
                    # Close all connections for this client
                    for connection in self.active_connections[client_id].copy():
                        try:
                            await connection.close()
                        except Exception:
                            pass

                    # Clean up
                    del self.active_connections[client_id]
                    del self.connection_metadata[client_id]
                    cleaned_count += 1

                    logger.info(f"[CLEANUP] Cleaned up inactive client: {client_id}")

        return cleaned_count

    async def send_agent_status_update(self, agent_id: str, status: Dict[str, Any]) -> None:
        """Send agent status update to all connected clients"""
        message = {
            "type": "agent_status_update",
            "agent_id": agent_id,
            "status": status,
            "timestamp": datetime.utcnow().isoformat(),
        }

        await self.broadcast_message(message)

    async def send_job_progress_update(self, job_id: str, progress: float, client_id: str = None) -> None:
        """Send job progress update"""
        message = {
            "type": "job_progress",
            "job_id": job_id,
            "progress": progress,
            "timestamp": datetime.utcnow().isoformat(),
        }

        if client_id:
            await self.send_personal_message(message, client_id)
        else:
            await self.broadcast_message(message)

    async def send_search_results_update(self, job_id: str, results: list, client_id: str) -> None:
        """Send search results update"""
        message = {
            "type": "search_results",
            "job_id": job_id,
            "results": results,
            "timestamp": datetime.utcnow().isoformat(),
        }

        await self.send_personal_message(message, client_id)

    async def send_visualization_update(self, job_id: str, visualization_data: Dict, client_id: str) -> None:
        """Send visualization update"""
        message = {
            "type": "visualization_update",
            "job_id": job_id,
            "visualization": visualization_data,
            "timestamp": datetime.utcnow().isoformat(),
        }

        await self.send_personal_message(message, client_id)

    async def send_error_notification(self, error_message: str, client_id: str = None) -> None:
        """Send error notification"""
        message = {
            "type": "error_notification",
            "message": error_message,
            "timestamp": datetime.utcnow().isoformat(),
        }

        if client_id:
            await self.send_personal_message(message, client_id)
        else:
            await self.broadcast_message(message)

    async def send_system_notification(self, notification: str, level: str = "info") -> None:
        """Send system-wide notification"""
        message = {
            "type": "system_notification",
            "message": notification,
            "level": level,  # info, warning, error
            "timestamp": datetime.utcnow().isoformat(),
        }

        await self.broadcast_message(message)

    def get_connected_clients(self) -> list:
        """Get list of connected client IDs"""
        return list(self.active_connections.keys())

    def is_client_connected(self, client_id: str) -> bool:
        """Check if a client is connected"""
        return client_id in self.active_connections and len(self.active_connections[client_id]) > 0

    async def cleanup(self) -> None:
        """Clean up all connections"""
        logger.info("[CLEANUP] Cleaning up WebSocket manager")

        # Close all connections
        for client_id, connections in self.active_connections.items():
            for connection in connections:
                try:
                    await connection.close()
                except Exception:
                    pass

        # Clear all data
        self.active_connections.clear()
        self.connection_metadata.clear()

        logger.info("[OK] WebSocket manager cleanup complete")
