"""
WebSocket Infrastructure Package
"""

from .connection_manager import (
    ConnectionInfo,
    ConnectionManager,
    ConnectionState,
    MessageType,
    WebSocketMessage,
    connection_manager,
)
from .message_queue import (
    MessagePriority,
    MessageQueue,
    MessageStatus,
    QueuedMessage,
    message_queue,
)
from .realtime_service import (
    RealtimeService,
    SearchEventType,
    SearchPhase,
    SearchProgress,
    SearchSession,
    realtime_service,
)
from .room_manager import RoomInfo, RoomManager, RoomType, room_manager

__all__ = [
    # Connection Manager
    "ConnectionManager",
    "ConnectionState",
    "ConnectionInfo",
    "WebSocketMessage",
    "MessageType",
    "connection_manager",
    # Room Manager
    "RoomManager",
    "RoomType",
    "RoomInfo",
    "room_manager",
    # Message Queue
    "MessageQueue",
    "MessagePriority",
    "MessageStatus",
    "QueuedMessage",
    "message_queue",
    # Real-time Service
    "RealtimeService",
    "SearchEventType",
    "SearchPhase",
    "SearchProgress",
    "SearchSession",
    "realtime_service",
]


async def initialize_websocket_infrastructure():
    """
    Initialize all WebSocket infrastructure components
    """
    # Start connection manager
    await connection_manager.start()

    # Start room manager
    await room_manager.start()

    # Start message queue
    await message_queue.start()

    # Start real-time service
    await realtime_service.start()


async def shutdown_websocket_infrastructure():
    """
    Shutdown all WebSocket infrastructure components
    """
    # Stop real-time service
    await realtime_service.stop()

    # Stop message queue
    await message_queue.stop()

    # Stop room manager
    await room_manager.stop()

    # Stop connection manager
    await connection_manager.stop()
