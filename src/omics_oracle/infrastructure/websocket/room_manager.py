"""
WebSocket Room Manager for Group Communication
"""

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

from .connection_manager import (
    MessageType,
    WebSocketMessage,
    connection_manager,
)


class RoomType(Enum):
    """Types of WebSocket rooms"""

    SEARCH_SESSION = "search_session"
    USER_PRIVATE = "user_private"
    BROADCAST = "broadcast"
    ADMIN = "admin"
    ANALYTICS = "analytics"


@dataclass
class RoomInfo:
    """Room information and metadata"""

    room_id: str
    room_type: RoomType
    name: str
    description: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    created_by: Optional[str] = None
    max_connections: int = 100
    is_private: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Connection tracking
    connections: Set[str] = field(default_factory=set)
    connection_count: int = 0

    # Activity tracking
    last_activity: float = field(default_factory=time.time)
    message_count: int = 0

    # Room settings
    auto_cleanup: bool = True
    cleanup_timeout: int = 3600  # 1 hour
    persist_messages: bool = False
    max_message_history: int = 100


class RoomManager:
    """
    Advanced room management for WebSocket connections
    """

    def __init__(self):
        self._rooms: Dict[str, RoomInfo] = {}
        self._user_rooms: Dict[str, Set[str]] = {}  # user_id -> room_ids
        self._connection_rooms: Dict[
            str, Set[str]
        ] = {}  # connection_id -> room_ids

        # Room templates for auto-creation
        self._room_templates: Dict[RoomType, RoomInfo] = {}

        # Message history (if enabled)
        self._message_history: Dict[str, List[WebSocketMessage]] = {}

        # Room callbacks
        self._room_created_callbacks: List[Callable] = []
        self._room_destroyed_callbacks: List[Callable] = []
        self._user_joined_callbacks: List[Callable] = []
        self._user_left_callbacks: List[Callable] = []

        # Cleanup task
        self._cleanup_task: Optional[asyncio.Task] = None

        # Statistics
        self.stats = {
            "total_rooms_created": 0,
            "active_rooms": 0,
            "total_joins": 0,
            "total_leaves": 0,
            "messages_sent": 0,
            "rooms_auto_cleaned": 0,
        }

        self.logger = logging.getLogger(__name__)

    async def start(self):
        """Start the room manager"""
        self.logger.info("Starting WebSocket room manager")

        # Create default rooms
        await self._create_default_rooms()

        # Start cleanup task
        self._cleanup_task = asyncio.create_task(self._auto_cleanup())

        self.logger.info("WebSocket room manager started")

    async def stop(self):
        """Stop the room manager"""
        self.logger.info("Stopping WebSocket room manager")

        # Cancel cleanup task
        if self._cleanup_task:
            self._cleanup_task.cancel()

        # Cleanup all rooms
        await self._cleanup_all_rooms()

        self.logger.info("WebSocket room manager stopped")

    async def create_room(
        self,
        room_type: RoomType,
        name: str,
        created_by: Optional[str] = None,
        description: Optional[str] = None,
        max_connections: int = 100,
        is_private: bool = False,
        **metadata,
    ) -> str:
        """
        Create a new room
        """
        room_id = str(uuid.uuid4())

        room_info = RoomInfo(
            room_id=room_id,
            room_type=room_type,
            name=name,
            description=description,
            created_by=created_by,
            max_connections=max_connections,
            is_private=is_private,
            metadata=metadata,
        )

        self._rooms[room_id] = room_info

        # Initialize message history if enabled
        if room_info.persist_messages:
            self._message_history[room_id] = []

        # Update statistics
        self.stats["total_rooms_created"] += 1
        self.stats["active_rooms"] = len(self._rooms)

        # Notify callbacks
        for callback in self._room_created_callbacks:
            try:
                await callback(room_id, room_info)
            except Exception as e:
                self.logger.error(f"Room created callback error: {e}")

        self.logger.info(f"Room created: {room_id} ({name})")
        return room_id

    async def destroy_room(self, room_id: str, reason: str = "Manual deletion"):
        """
        Destroy a room and disconnect all users
        """
        if room_id not in self._rooms:
            return False

        room_info = self._rooms[room_id]

        # Disconnect all connections from the room
        connection_ids = room_info.connections.copy()
        for connection_id in connection_ids:
            await self.leave_room(connection_id, room_id)

        # Notify callbacks
        for callback in self._room_destroyed_callbacks:
            try:
                await callback(room_id, room_info, reason)
            except Exception as e:
                self.logger.error(f"Room destroyed callback error: {e}")

        # Remove room
        del self._rooms[room_id]

        # Remove message history
        if room_id in self._message_history:
            del self._message_history[room_id]

        # Update statistics
        self.stats["active_rooms"] = len(self._rooms)

        self.logger.info(f"Room destroyed: {room_id} - {reason}")
        return True

    async def join_room(
        self, connection_id: str, room_id: str, user_id: Optional[str] = None
    ) -> bool:
        """
        Join a connection to a room
        """
        if room_id not in self._rooms:
            self.logger.warning(
                f"Attempted to join non-existent room: {room_id}"
            )
            return False

        room_info = self._rooms[room_id]

        # Check room capacity
        if room_info.connection_count >= room_info.max_connections:
            self.logger.warning(f"Room {room_id} is at capacity")
            return False

        # Check if already in room
        if connection_id in room_info.connections:
            return True

        # Add to room
        room_info.connections.add(connection_id)
        room_info.connection_count += 1
        room_info.last_activity = time.time()

        # Track connection rooms
        if connection_id not in self._connection_rooms:
            self._connection_rooms[connection_id] = set()
        self._connection_rooms[connection_id].add(room_id)

        # Track user rooms
        if user_id:
            if user_id not in self._user_rooms:
                self._user_rooms[user_id] = set()
            self._user_rooms[user_id].add(room_id)

        # Join room in connection manager
        await connection_manager.join_room(connection_id, room_id)

        # Update statistics
        self.stats["total_joins"] += 1

        # Notify callbacks
        for callback in self._user_joined_callbacks:
            try:
                await callback(connection_id, room_id, user_id)
            except Exception as e:
                self.logger.error(f"User joined callback error: {e}")

        # Send room history if enabled
        if room_info.persist_messages and room_id in self._message_history:
            history = self._message_history[room_id][-10:]  # Last 10 messages
            for msg in history:
                await connection_manager.send_message(connection_id, msg)

        self.logger.info(f"Connection {connection_id} joined room {room_id}")
        return True

    async def leave_room(
        self, connection_id: str, room_id: str, user_id: Optional[str] = None
    ) -> bool:
        """
        Remove a connection from a room
        """
        if room_id not in self._rooms:
            return False

        room_info = self._rooms[room_id]

        # Check if in room
        if connection_id not in room_info.connections:
            return True

        # Remove from room
        room_info.connections.remove(connection_id)
        room_info.connection_count -= 1
        room_info.last_activity = time.time()

        # Remove from connection rooms
        if connection_id in self._connection_rooms:
            self._connection_rooms[connection_id].discard(room_id)
            if not self._connection_rooms[connection_id]:
                del self._connection_rooms[connection_id]

        # Remove from user rooms
        if user_id and user_id in self._user_rooms:
            self._user_rooms[user_id].discard(room_id)
            if not self._user_rooms[user_id]:
                del self._user_rooms[user_id]

        # Leave room in connection manager
        await connection_manager.leave_room(connection_id, room_id)

        # Update statistics
        self.stats["total_leaves"] += 1

        # Notify callbacks
        for callback in self._user_left_callbacks:
            try:
                await callback(connection_id, room_id, user_id)
            except Exception as e:
                self.logger.error(f"User left callback error: {e}")

        # Auto-cleanup empty rooms
        if (
            room_info.auto_cleanup
            and room_info.connection_count == 0
            and room_info.room_type == RoomType.SEARCH_SESSION
        ):
            await self.destroy_room(room_id, "Auto-cleanup: empty room")

        self.logger.info(f"Connection {connection_id} left room {room_id}")
        return True

    async def send_to_room(
        self,
        room_id: str,
        message: WebSocketMessage,
        exclude_connections: Optional[Set[str]] = None,
    ) -> int:
        """
        Send message to all connections in a room
        """
        if room_id not in self._rooms:
            return 0

        room_info = self._rooms[room_id]

        # Set room_id in message
        message.room_id = room_id

        # Store message history if enabled
        if room_info.persist_messages:
            if room_id not in self._message_history:
                self._message_history[room_id] = []

            self._message_history[room_id].append(message)

            # Limit history size
            if (
                len(self._message_history[room_id])
                > room_info.max_message_history
            ):
                self._message_history[room_id] = self._message_history[room_id][
                    -room_info.max_message_history :
                ]

        # Send to connection manager
        await connection_manager.send_to_room(
            room_id, message, exclude_connections
        )

        # Update room activity
        room_info.last_activity = time.time()
        room_info.message_count += 1

        # Update statistics
        self.stats["messages_sent"] += 1

        return room_info.connection_count

    async def broadcast_to_type(
        self,
        room_type: RoomType,
        message: WebSocketMessage,
        exclude_rooms: Optional[Set[str]] = None,
    ) -> int:
        """
        Broadcast message to all rooms of a specific type
        """
        if exclude_rooms is None:
            exclude_rooms = set()

        sent_count = 0

        for room_id, room_info in self._rooms.items():
            if (
                room_info.room_type == room_type
                and room_id not in exclude_rooms
            ):
                count = await self.send_to_room(room_id, message)
                sent_count += count

        return sent_count

    async def get_or_create_user_room(self, user_id: str) -> str:
        """
        Get or create a private room for a user
        """
        # Check if user already has a private room
        if user_id in self._user_rooms:
            for room_id in self._user_rooms[user_id]:
                room_info = self._rooms.get(room_id)
                if room_info and room_info.room_type == RoomType.USER_PRIVATE:
                    return room_id

        # Create new private room
        room_id = await self.create_room(
            room_type=RoomType.USER_PRIVATE,
            name=f"User {user_id} Private Room",
            created_by=user_id,
            is_private=True,
            max_connections=5,
            user_id=user_id,
        )

        return room_id

    async def get_or_create_search_room(
        self, search_id: str, user_id: Optional[str] = None
    ) -> str:
        """
        Get or create a room for a search session
        """
        # Look for existing search room
        for room_id, room_info in self._rooms.items():
            if (
                room_info.room_type == RoomType.SEARCH_SESSION
                and room_info.metadata.get("search_id") == search_id
            ):
                return room_id

        # Create new search room
        room_id = await self.create_room(
            room_type=RoomType.SEARCH_SESSION,
            name=f"Search Session {search_id[:8]}",
            created_by=user_id,
            description=f"Real-time updates for search {search_id}",
            max_connections=10,
            search_id=search_id,
            auto_cleanup=True,
            cleanup_timeout=1800,  # 30 minutes
        )

        return room_id

    async def _create_default_rooms(self):
        """Create default system rooms"""

        # Global broadcast room
        await self.create_room(
            room_type=RoomType.BROADCAST,
            name="Global Broadcast",
            description="System-wide announcements",
            max_connections=1000,
            auto_cleanup=False,
        )

        # Admin room
        await self.create_room(
            room_type=RoomType.ADMIN,
            name="Admin Room",
            description="Administrative communications",
            is_private=True,
            max_connections=50,
            auto_cleanup=False,
        )

        # Analytics room
        await self.create_room(
            room_type=RoomType.ANALYTICS,
            name="Analytics Room",
            description="Real-time analytics and monitoring",
            max_connections=100,
            auto_cleanup=False,
            persist_messages=True,
        )

    async def _auto_cleanup(self):
        """
        Automatically cleanup inactive rooms
        """
        while True:
            try:
                current_time = time.time()
                rooms_to_cleanup = []

                for room_id, room_info in self._rooms.items():
                    if (
                        room_info.auto_cleanup
                        and room_info.connection_count == 0
                        and (current_time - room_info.last_activity)
                        > room_info.cleanup_timeout
                    ):
                        rooms_to_cleanup.append(room_id)

                # Cleanup inactive rooms
                for room_id in rooms_to_cleanup:
                    await self.destroy_room(room_id, "Auto-cleanup: inactive")
                    self.stats["rooms_auto_cleaned"] += 1

                # Wait before next cleanup
                await asyncio.sleep(300)  # Check every 5 minutes

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Auto cleanup error: {e}")
                await asyncio.sleep(300)

    async def _cleanup_all_rooms(self):
        """Cleanup all rooms"""
        room_ids = list(self._rooms.keys())

        for room_id in room_ids:
            await self.destroy_room(room_id, "System shutdown")

    # Callback management
    def add_room_created_callback(self, callback: Callable):
        """Add callback for room creation"""
        self._room_created_callbacks.append(callback)

    def add_room_destroyed_callback(self, callback: Callable):
        """Add callback for room destruction"""
        self._room_destroyed_callbacks.append(callback)

    def add_user_joined_callback(self, callback: Callable):
        """Add callback for user joining room"""
        self._user_joined_callbacks.append(callback)

    def add_user_left_callback(self, callback: Callable):
        """Add callback for user leaving room"""
        self._user_left_callbacks.append(callback)

    # Information getters
    def get_room_info(self, room_id: str) -> Optional[RoomInfo]:
        """Get room information"""
        return self._rooms.get(room_id)

    def get_user_rooms(self, user_id: str) -> Set[str]:
        """Get all rooms a user is in"""
        return self._user_rooms.get(user_id, set()).copy()

    def get_connection_rooms(self, connection_id: str) -> Set[str]:
        """Get all rooms a connection is in"""
        return self._connection_rooms.get(connection_id, set()).copy()

    def list_rooms(
        self, room_type: Optional[RoomType] = None
    ) -> List[RoomInfo]:
        """List all rooms, optionally filtered by type"""
        if room_type is None:
            return list(self._rooms.values())

        return [
            room for room in self._rooms.values() if room.room_type == room_type
        ]

    def get_statistics(self) -> Dict[str, Any]:
        """Get room statistics"""
        room_type_counts = {}
        for room in self._rooms.values():
            room_type = room.room_type.value
            room_type_counts[room_type] = room_type_counts.get(room_type, 0) + 1

        return {
            **self.stats,
            "room_type_counts": room_type_counts,
            "total_connections_in_rooms": sum(
                room.connection_count for room in self._rooms.values()
            ),
            "average_room_size": sum(
                room.connection_count for room in self._rooms.values()
            )
            / max(len(self._rooms), 1),
        }


# Global room manager instance
room_manager = RoomManager()
