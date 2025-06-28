"""
Enhanced WebSocket Infrastructure for Real-Time Communication
"""

import asyncio
import json
import logging
import time
import uuid
import weakref
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

from fastapi import WebSocket, WebSocketDisconnect


class ConnectionState(Enum):
    """WebSocket connection states"""

    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTING = "disconnecting"
    DISCONNECTED = "disconnected"
    ERROR = "error"


class MessageType(Enum):
    """WebSocket message types"""

    SEARCH_PROGRESS = "search_progress"
    SEARCH_RESULT = "search_result"
    SEARCH_ERROR = "search_error"
    SEARCH_COMPLETE = "search_complete"
    SYSTEM_MESSAGE = "system_message"
    HEARTBEAT = "heartbeat"
    ROOM_JOIN = "room_join"
    ROOM_LEAVE = "room_leave"


@dataclass
class WebSocketMessage:
    """Structured WebSocket message"""

    type: MessageType
    data: Any
    timestamp: float = None
    message_id: str = None
    room_id: Optional[str] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()
        if self.message_id is None:
            self.message_id = str(uuid.uuid4())

    def to_dict(self) -> Dict:
        """Convert message to dictionary for JSON serialization"""
        return {
            "type": self.type.value,
            "data": self.data,
            "timestamp": self.timestamp,
            "message_id": self.message_id,
            "room_id": self.room_id,
        }

    def to_json(self) -> str:
        """Convert message to JSON string"""
        return json.dumps(self.to_dict())


@dataclass
class ConnectionInfo:
    """WebSocket connection information"""

    connection_id: str
    websocket: WebSocket
    user_id: Optional[str] = None
    rooms: Set[str] = None
    connected_at: float = None
    last_heartbeat: float = None
    state: ConnectionState = ConnectionState.CONNECTING
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.rooms is None:
            self.rooms = set()
        if self.connected_at is None:
            self.connected_at = time.time()
        if self.last_heartbeat is None:
            self.last_heartbeat = time.time()
        if self.metadata is None:
            self.metadata = {}


class ConnectionManager:
    """
    Advanced WebSocket connection manager with pooling and health monitoring
    """

    def __init__(
        self,
        heartbeat_interval: int = 30,
        connection_timeout: int = 300,
        max_connections: int = 1000,
    ):
        self.heartbeat_interval = heartbeat_interval
        self.connection_timeout = connection_timeout
        self.max_connections = max_connections

        # Connection storage
        self._connections: Dict[str, ConnectionInfo] = {}
        self._user_connections: Dict[str, Set[str]] = {}
        self._room_connections: Dict[str, Set[str]] = {}

        # Connection pool management
        self._connection_pool_size = 0
        self._connection_pool_lock = asyncio.Lock()

        # Health monitoring
        self._health_monitor_task: Optional[asyncio.Task] = None
        self._heartbeat_task: Optional[asyncio.Task] = None

        # Callbacks
        self._connection_callbacks: List[Callable] = []
        self._disconnection_callbacks: List[Callable] = []

        # Statistics
        self.stats = {
            "total_connections": 0,
            "active_connections": 0,
            "messages_sent": 0,
            "messages_received": 0,
            "connection_errors": 0,
            "heartbeat_failures": 0,
        }

        self.logger = logging.getLogger(__name__)

    async def start(self):
        """Start the connection manager"""
        self.logger.info("Starting WebSocket connection manager")

        # Start health monitoring
        self._health_monitor_task = asyncio.create_task(self._health_monitor())
        self._heartbeat_task = asyncio.create_task(self._send_heartbeats())

        self.logger.info("WebSocket connection manager started")

    async def stop(self):
        """Stop the connection manager and cleanup"""
        self.logger.info("Stopping WebSocket connection manager")

        # Cancel monitoring tasks
        if self._health_monitor_task:
            self._health_monitor_task.cancel()
        if self._heartbeat_task:
            self._heartbeat_task.cancel()

        # Disconnect all connections
        await self._disconnect_all()

        self.logger.info("WebSocket connection manager stopped")

    async def connect(self, websocket: WebSocket, user_id: Optional[str] = None) -> str:
        """
        Connect a new WebSocket with connection pooling
        """
        if self._connection_pool_size >= self.max_connections:
            raise ConnectionError(f"Maximum connections ({self.max_connections}) reached")

        connection_id = str(uuid.uuid4())

        try:
            # Accept WebSocket connection
            await websocket.accept()

            # Create connection info
            connection_info = ConnectionInfo(
                connection_id=connection_id,
                websocket=websocket,
                user_id=user_id,
                state=ConnectionState.CONNECTED,
            )

            async with self._connection_pool_lock:
                # Store connection
                self._connections[connection_id] = connection_info

                # Track user connections
                if user_id:
                    if user_id not in self._user_connections:
                        self._user_connections[user_id] = set()
                    self._user_connections[user_id].add(connection_id)

                # Update pool size
                self._connection_pool_size += 1

                # Update statistics
                self.stats["total_connections"] += 1
                self.stats["active_connections"] = self._connection_pool_size

            # Notify callbacks
            for callback in self._connection_callbacks:
                try:
                    await callback(connection_id, connection_info)
                except Exception as e:
                    self.logger.error(f"Connection callback error: {e}")

            self.logger.info(f"WebSocket connected: {connection_id} (user: {user_id})")
            return connection_id

        except Exception as e:
            self.stats["connection_errors"] += 1
            self.logger.error(f"Connection error: {e}")
            raise

    async def disconnect(self, connection_id: str, reason: str = "Normal closure"):
        """
        Disconnect a WebSocket connection
        """
        if connection_id not in self._connections:
            return

        connection_info = self._connections[connection_id]

        try:
            # Update connection state
            connection_info.state = ConnectionState.DISCONNECTING

            # Leave all rooms
            for room_id in connection_info.rooms.copy():
                await self.leave_room(connection_id, room_id)

            # Close WebSocket
            try:
                await connection_info.websocket.close()
            except Exception as e:
                self.logger.warning(f"Error closing WebSocket: {e}")

            # Update connection state
            connection_info.state = ConnectionState.DISCONNECTED

            # Notify callbacks
            for callback in self._disconnection_callbacks:
                try:
                    await callback(connection_id, connection_info, reason)
                except Exception as e:
                    self.logger.error(f"Disconnection callback error: {e}")

        finally:
            # Remove from storage
            async with self._connection_pool_lock:
                if connection_id in self._connections:
                    del self._connections[connection_id]

                # Remove from user connections
                if connection_info.user_id:
                    if connection_info.user_id in self._user_connections:
                        self._user_connections[connection_info.user_id].discard(connection_id)
                        if not self._user_connections[connection_info.user_id]:
                            del self._user_connections[connection_info.user_id]

                # Update pool size
                self._connection_pool_size -= 1
                self.stats["active_connections"] = self._connection_pool_size

            self.logger.info(f"WebSocket disconnected: {connection_id} - {reason}")

    async def send_message(self, connection_id: str, message: WebSocketMessage) -> bool:
        """
        Send message to a specific connection
        """
        if connection_id not in self._connections:
            return False

        connection_info = self._connections[connection_id]

        if connection_info.state != ConnectionState.CONNECTED:
            return False

        try:
            await connection_info.websocket.send_text(message.to_json())
            self.stats["messages_sent"] += 1
            return True

        except WebSocketDisconnect:
            await self.disconnect(connection_id, "WebSocket disconnected")
            return False
        except Exception as e:
            self.logger.error(f"Error sending message to {connection_id}: {e}")
            return False

    async def send_to_user(self, user_id: str, message: WebSocketMessage):
        """
        Send message to all connections of a user
        """
        if user_id not in self._user_connections:
            return

        connection_ids = self._user_connections[user_id].copy()

        for connection_id in connection_ids:
            await self.send_message(connection_id, message)

    async def broadcast(self, message: WebSocketMessage, exclude: Optional[Set[str]] = None):
        """
        Broadcast message to all connections
        """
        if exclude is None:
            exclude = set()

        connection_ids = list(self._connections.keys())

        for connection_id in connection_ids:
            if connection_id not in exclude:
                await self.send_message(connection_id, message)

    async def join_room(self, connection_id: str, room_id: str):
        """
        Join a connection to a room
        """
        if connection_id not in self._connections:
            return False

        connection_info = self._connections[connection_id]

        # Add to room
        connection_info.rooms.add(room_id)

        # Track room connections
        if room_id not in self._room_connections:
            self._room_connections[room_id] = set()
        self._room_connections[room_id].add(connection_id)

        self.logger.info(f"Connection {connection_id} joined room {room_id}")
        return True

    async def leave_room(self, connection_id: str, room_id: str):
        """
        Remove a connection from a room
        """
        if connection_id not in self._connections:
            return False

        connection_info = self._connections[connection_id]

        # Remove from room
        connection_info.rooms.discard(room_id)

        # Remove from room connections
        if room_id in self._room_connections:
            self._room_connections[room_id].discard(connection_id)
            if not self._room_connections[room_id]:
                del self._room_connections[room_id]

        self.logger.info(f"Connection {connection_id} left room {room_id}")
        return True

    async def send_to_room(
        self,
        room_id: str,
        message: WebSocketMessage,
        exclude: Optional[Set[str]] = None,
    ):
        """
        Send message to all connections in a room
        """
        if room_id not in self._room_connections:
            return

        if exclude is None:
            exclude = set()

        connection_ids = self._room_connections[room_id].copy()

        for connection_id in connection_ids:
            if connection_id not in exclude:
                await self.send_message(connection_id, message)

    async def receive_message(self, connection_id: str) -> Optional[Dict]:
        """
        Receive message from a connection
        """
        if connection_id not in self._connections:
            return None

        connection_info = self._connections[connection_id]

        try:
            data = await connection_info.websocket.receive_text()
            self.stats["messages_received"] += 1

            # Update heartbeat
            connection_info.last_heartbeat = time.time()

            return json.loads(data)

        except WebSocketDisconnect:
            await self.disconnect(connection_id, "WebSocket disconnected")
            return None
        except Exception as e:
            self.logger.error(f"Error receiving message from {connection_id}: {e}")
            return None

    async def _health_monitor(self):
        """
        Monitor connection health and cleanup stale connections
        """
        while True:
            try:
                current_time = time.time()
                stale_connections = []

                for connection_id, connection_info in self._connections.items():
                    # Check for stale connections
                    if (current_time - connection_info.last_heartbeat) > self.connection_timeout:
                        stale_connections.append(connection_id)

                # Disconnect stale connections
                for connection_id in stale_connections:
                    await self.disconnect(connection_id, "Connection timeout")

                # Wait before next check
                await asyncio.sleep(60)  # Check every minute

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Health monitor error: {e}")
                await asyncio.sleep(60)

    async def _send_heartbeats(self):
        """
        Send heartbeat messages to all connections
        """
        while True:
            try:
                heartbeat_message = WebSocketMessage(
                    type=MessageType.HEARTBEAT, data={"timestamp": time.time()}
                )

                connection_ids = list(self._connections.keys())

                for connection_id in connection_ids:
                    success = await self.send_message(connection_id, heartbeat_message)
                    if not success:
                        self.stats["heartbeat_failures"] += 1

                await asyncio.sleep(self.heartbeat_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Heartbeat error: {e}")
                await asyncio.sleep(self.heartbeat_interval)

    async def _disconnect_all(self):
        """
        Disconnect all connections
        """
        connection_ids = list(self._connections.keys())

        for connection_id in connection_ids:
            await self.disconnect(connection_id, "Server shutdown")

    def add_connection_callback(self, callback: Callable):
        """Add callback for new connections"""
        self._connection_callbacks.append(callback)

    def add_disconnection_callback(self, callback: Callable):
        """Add callback for disconnections"""
        self._disconnection_callbacks.append(callback)

    def get_connection_info(self, connection_id: str) -> Optional[ConnectionInfo]:
        """Get connection information"""
        return self._connections.get(connection_id)

    def get_user_connections(self, user_id: str) -> Set[str]:
        """Get all connection IDs for a user"""
        return self._user_connections.get(user_id, set()).copy()

    def get_room_connections(self, room_id: str) -> Set[str]:
        """Get all connection IDs in a room"""
        return self._room_connections.get(room_id, set()).copy()

    def get_statistics(self) -> Dict[str, Any]:
        """Get connection statistics"""
        return {
            **self.stats,
            "connection_pool_size": self._connection_pool_size,
            "active_rooms": len(self._room_connections),
            "active_users": len(self._user_connections),
        }

    @asynccontextmanager
    async def connection_context(self, websocket: WebSocket, user_id: Optional[str] = None):
        """
        Context manager for WebSocket connections
        """
        connection_id = None
        try:
            connection_id = await self.connect(websocket, user_id)
            yield connection_id
        except Exception as e:
            self.logger.error(f"Connection context error: {e}")
            raise
        finally:
            if connection_id:
                await self.disconnect(connection_id, "Context closed")


# Global connection manager instance
connection_manager = ConnectionManager()
