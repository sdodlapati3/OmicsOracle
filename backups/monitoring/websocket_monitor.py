"""
WebSocket monitoring module for OmicsOracle.

This module provides utilities for monitoring WebSocket connections and messages.
"""

import json
import logging
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from fastapi import FastAPI, WebSocket

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class WebSocketMonitor:
    """Monitor WebSocket connections and messages."""

    def __init__(self, log_to_file: bool = True, log_dir: str = "logs"):
        """Initialize the WebSocket monitor."""
        self.connections: Dict[str, Dict[str, Any]] = {}
        self.message_count = 0
        self.error_count = 0
        self.start_time = time.time()

        # Logging to file
        self.log_to_file = log_to_file
        self.log_dir = Path(log_dir)

        if self.log_to_file:
            self.log_dir.mkdir(exist_ok=True)
            self.message_log_file = self.log_dir / "websocket_messages.jsonl"
            self.connection_log_file = self.log_dir / "websocket_connections.jsonl"
            self.stats_file = self.log_dir / "websocket_stats.json"

    async def connect(self, websocket: WebSocket) -> str:
        """Track a new WebSocket connection."""
        # Generate connection ID
        connection_id = str(uuid.uuid4())

        # Store connection info
        connection_info = {
            "id": connection_id,
            "client": websocket.client.host if websocket.client else "unknown",
            "port": websocket.client.port if websocket.client else 0,
            "path": websocket.url.path,
            "connected_at": time.time(),
            "connected_at_readable": datetime.fromtimestamp(time.time()).strftime("%Y-%m-%d %H:%M:%S.%f"),
            "messages_sent": 0,
            "messages_received": 0,
            "errors": 0,
            "last_activity": time.time(),
            "last_activity_readable": datetime.fromtimestamp(time.time()).strftime("%Y-%m-%d %H:%M:%S.%f"),
        }

        self.connections[connection_id] = connection_info

        # Log connection
        logger.info(f"WebSocket connected: {connection_id} from {connection_info['client']}")

        if self.log_to_file:
            with open(self.connection_log_file, "a") as f:
                f.write(json.dumps({**connection_info, "event": "connect"}) + "\n")

            self.update_stats()

        return connection_id

    def disconnect(self, connection_id: str) -> None:
        """Track a WebSocket disconnection."""
        if connection_id in self.connections:
            connection_info = self.connections[connection_id]

            # Calculate duration
            duration = time.time() - connection_info["connected_at"]

            # Log disconnection
            logger.info(f"WebSocket disconnected: {connection_id} after {duration:.2f}s")

            if self.log_to_file:
                with open(self.connection_log_file, "a") as f:
                    f.write(
                        json.dumps(
                            {
                                **connection_info,
                                "event": "disconnect",
                                "duration": duration,
                                "disconnected_at": time.time(),
                                "disconnected_at_readable": datetime.fromtimestamp(time.time()).strftime(
                                    "%Y-%m-%d %H:%M:%S.%f"
                                ),
                            }
                        )
                        + "\n"
                    )

            # Remove connection
            del self.connections[connection_id]

            self.update_stats()

    async def message_received(self, connection_id: str, message: str) -> None:
        """Track a message received from a client."""
        self.message_count += 1

        if connection_id in self.connections:
            connection = self.connections[connection_id]
            connection["messages_received"] += 1
            connection["last_activity"] = time.time()
            connection["last_activity_readable"] = datetime.fromtimestamp(time.time()).strftime(
                "%Y-%m-%d %H:%M:%S.%f"
            )

        # Log message
        if self.log_to_file:
            # Truncate message if too long
            max_message_length = 1024 * 10  # 10KB
            logged_message = message
            if len(message) > max_message_length:
                logged_message = message[:max_message_length] + "... [truncated]"

            with open(self.message_log_file, "a") as f:
                f.write(
                    json.dumps(
                        {
                            "connection_id": connection_id,
                            "direction": "received",
                            "timestamp": time.time(),
                            "timestamp_readable": datetime.fromtimestamp(time.time()).strftime(
                                "%Y-%m-%d %H:%M:%S.%f"
                            ),
                            "message": logged_message,
                            "message_length": len(message),
                        }
                    )
                    + "\n"
                )

            if self.message_count % 10 == 0:
                self.update_stats()

    async def message_sent(self, connection_id: str, message: Any) -> None:
        """Track a message sent to a client."""
        self.message_count += 1

        if connection_id in self.connections:
            connection = self.connections[connection_id]
            connection["messages_sent"] += 1
            connection["last_activity"] = time.time()
            connection["last_activity_readable"] = datetime.fromtimestamp(time.time()).strftime(
                "%Y-%m-%d %H:%M:%S.%f"
            )

        # Log message
        if self.log_to_file:
            # Convert message to string if it's not already
            if not isinstance(message, str):
                try:
                    message = json.dumps(message)
                except Exception:
                    message = str(message)

            # Truncate message if too long
            max_message_length = 1024 * 10  # 10KB
            logged_message = message
            if len(message) > max_message_length:
                logged_message = message[:max_message_length] + "... [truncated]"

            with open(self.message_log_file, "a") as f:
                f.write(
                    json.dumps(
                        {
                            "connection_id": connection_id,
                            "direction": "sent",
                            "timestamp": time.time(),
                            "timestamp_readable": datetime.fromtimestamp(time.time()).strftime(
                                "%Y-%m-%d %H:%M:%S.%f"
                            ),
                            "message": logged_message,
                            "message_length": len(message),
                        }
                    )
                    + "\n"
                )

            if self.message_count % 10 == 0:
                self.update_stats()

    async def error(self, connection_id: str, error: Exception) -> None:
        """Track an error on a WebSocket connection."""
        self.error_count += 1

        if connection_id in self.connections:
            connection = self.connections[connection_id]
            connection["errors"] += 1
            connection["last_activity"] = time.time()
            connection["last_activity_readable"] = datetime.fromtimestamp(time.time()).strftime(
                "%Y-%m-%d %H:%M:%S.%f"
            )

        # Log error
        logger.error(f"WebSocket error on {connection_id}: {error}")

        if self.log_to_file:
            with open(self.message_log_file, "a") as f:
                f.write(
                    json.dumps(
                        {
                            "connection_id": connection_id,
                            "direction": "error",
                            "timestamp": time.time(),
                            "timestamp_readable": datetime.fromtimestamp(time.time()).strftime(
                                "%Y-%m-%d %H:%M:%S.%f"
                            ),
                            "error": str(error),
                            "error_type": type(error).__name__,
                        }
                    )
                    + "\n"
                )

            self.update_stats()

    def update_stats(self) -> None:
        """Update the WebSocket stats file."""
        if not self.log_to_file:
            return

        # Calculate stats
        active_connections = len(self.connections)
        total_messages_sent = sum(conn["messages_sent"] for conn in self.connections.values())
        total_messages_received = sum(conn["messages_received"] for conn in self.connections.values())

        # Create stats object
        stats = {
            "active_connections": active_connections,
            "total_connections": active_connections,  # We don't track historical connections here
            "message_count": self.message_count,
            "error_count": self.error_count,
            "messages_sent": total_messages_sent,
            "messages_received": total_messages_received,
            "uptime": time.time() - self.start_time,
            "uptime_readable": str(
                datetime.fromtimestamp(time.time()) - datetime.fromtimestamp(self.start_time)
            ),
            "timestamp": time.time(),
            "timestamp_readable": datetime.fromtimestamp(time.time()).strftime("%Y-%m-%d %H:%M:%S"),
        }

        # Write to file
        with open(self.stats_file, "w") as f:
            json.dump(stats, f, indent=2)


# Global monitor instance
global_monitor = WebSocketMonitor()


def get_monitor() -> WebSocketMonitor:
    """Get the global WebSocket monitor instance."""
    return global_monitor


class MonitoredConnectionManager:
    """Connection manager with built-in monitoring."""

    def __init__(self):
        """Initialize the connection manager."""
        self.active_connections: Dict[WebSocket, str] = {}
        self.monitor = get_monitor()

    async def connect(self, websocket: WebSocket) -> None:
        """Accept and track a new WebSocket connection."""
        await websocket.accept()
        connection_id = await self.monitor.connect(websocket)
        self.active_connections[websocket] = connection_id

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove and stop tracking a WebSocket connection."""
        if websocket in self.active_connections:
            connection_id = self.active_connections[websocket]
            self.monitor.disconnect(connection_id)
            del self.active_connections[websocket]

    async def send_text(self, websocket: WebSocket, message: str) -> None:
        """Send a text message and track it."""
        if websocket in self.active_connections:
            connection_id = self.active_connections[websocket]
            await websocket.send_text(message)
            await self.monitor.message_sent(connection_id, message)

    async def send_json(self, websocket: WebSocket, message: Any) -> None:
        """Send a JSON message and track it."""
        if websocket in self.active_connections:
            connection_id = self.active_connections[websocket]
            await websocket.send_json(message)
            await self.monitor.message_sent(connection_id, message)

    async def broadcast(self, message: str) -> None:
        """Broadcast a text message to all connected clients."""
        disconnected = []
        for websocket, connection_id in self.active_connections.items():
            try:
                await websocket.send_text(message)
                await self.monitor.message_sent(connection_id, message)
            except Exception as e:
                await self.monitor.error(connection_id, e)
                disconnected.append(websocket)

        # Remove disconnected clients
        for websocket in disconnected:
            self.disconnect(websocket)

    async def broadcast_json(self, message: Any) -> None:
        """Broadcast a JSON message to all connected clients."""
        disconnected = []
        for websocket, connection_id in self.active_connections.items():
            try:
                await websocket.send_json(message)
                await self.monitor.message_sent(connection_id, message)
            except Exception as e:
                await self.monitor.error(connection_id, e)
                disconnected.append(websocket)

        # Remove disconnected clients
        for websocket in disconnected:
            self.disconnect(websocket)

    async def receive(self, websocket: WebSocket) -> str:
        """Receive and track a message."""
        if websocket in self.active_connections:
            connection_id = self.active_connections[websocket]
            message = await websocket.receive_text()
            await self.monitor.message_received(connection_id, message)
            return message
        return ""


def setup_websocket_monitoring(app: FastAPI) -> MonitoredConnectionManager:
    """Set up WebSocket monitoring for a FastAPI app."""
    manager = MonitoredConnectionManager()
    app.state.ws_monitor = get_monitor()
    app.state.connection_manager = manager
    logger.info("WebSocket monitoring set up")
    return manager
