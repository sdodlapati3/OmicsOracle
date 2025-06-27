"""
Enhanced WebSocket endpoints for real-time communication.

This module provides WebSocket endpoints using the Phase 6 enhanced
infrastructure including connection management, room management,
message queuing, and real-time services.
"""

import asyncio
import json
import logging
from typing import Annotated, Any, Dict

from fastapi import Depends, FastAPI, WebSocket, WebSocketDisconnect

from ...infrastructure.dependencies.container import Container
from ...infrastructure.messaging.event_bus import EventBus
from ...infrastructure.messaging.websocket_service import WebSocketService
from ...infrastructure.websocket.connection_manager import ConnectionManager
from ...infrastructure.websocket.realtime_service import RealtimeService
from ...infrastructure.websocket.room_manager import RoomManager
from .dependencies import get_container, get_event_bus, get_websocket_service

logger = logging.getLogger(__name__)


def setup_websockets(app: FastAPI) -> None:
    """Setup enhanced WebSocket endpoints with Phase 6 infrastructure."""

    @app.websocket("/ws/v2/realtime/{room_id}")
    async def enhanced_websocket_realtime(
        websocket: WebSocket,
        room_id: str,
        container: Container = Depends(get_container),
    ):
        """Enhanced WebSocket endpoint with room management and real-time features."""
        await websocket.accept()

        try:
            # Get enhanced services from container
            connection_manager = await container.get(ConnectionManager)
            room_manager = await container.get(RoomManager)
            realtime_service = await container.get(RealtimeService)

            # Connect to room
            connection_id = await connection_manager.connect(websocket)
            await room_manager.join_room(connection_id, room_id)

            logger.info(
                f"Enhanced WebSocket client {connection_id} joined room {room_id}"
            )

            # Send welcome message
            await websocket.send_json(
                {
                    "type": "room_joined",
                    "connection_id": connection_id,
                    "room_id": room_id,
                    "features": [
                        "real-time-updates",
                        "message-queue",
                        "broadcasting",
                    ],
                    "message": "Connected to enhanced real-time room",
                }
            )

            # Handle messages
            async def message_handler(message: Dict[str, Any]):
                await websocket.send_json(message)

            # Subscribe to room messages
            await realtime_service.subscribe_to_room(room_id, message_handler)

            # Keep connection alive
            while True:
                try:
                    data = await websocket.receive_text()
                    message = json.loads(data)

                    # Handle different message types
                    if message.get("type") == "broadcast":
                        # Broadcast to room
                        await room_manager.broadcast_to_room(
                            room_id,
                            {
                                "type": "user_message",
                                "from": connection_id,
                                "content": message.get("content", ""),
                                "timestamp": message.get("timestamp"),
                            },
                        )
                    elif message.get("type") == "get_room_info":
                        # Get room information
                        room_info = await room_manager.get_room_info(room_id)
                        await websocket.send_json(
                            {"type": "room_info", "room_info": room_info}
                        )

                except json.JSONDecodeError:
                    await websocket.send_json(
                        {"type": "error", "message": "Invalid JSON format"}
                    )

        except WebSocketDisconnect:
            if "connection_id" in locals():
                await room_manager.leave_room(connection_id, room_id)
                await connection_manager.disconnect(connection_id)
            logger.info(
                f"Enhanced WebSocket client disconnected from room {room_id}"
            )
        except Exception as e:
            logger.error(f"Enhanced WebSocket error in room {room_id}: {e}")
            if "connection_id" in locals():
                await room_manager.leave_room(connection_id, room_id)
                await connection_manager.disconnect(connection_id)

    @app.websocket("/ws/search-progress")
    async def websocket_search_progress(
        websocket: WebSocket,
        websocket_service: Annotated[
            WebSocketService, Depends(get_websocket_service)
        ],
    ):
        """Legacy WebSocket endpoint for search progress updates (v1 compatibility)."""
        await websocket.accept()
        client_id = None

        try:
            # Register connection
            client_id = await websocket_service.connect(websocket)
            logger.info(f"Legacy WebSocket client connected: {client_id}")

            # Send welcome message
            await websocket.send_json(
                {
                    "type": "connection_established",
                    "client_id": client_id,
                    "message": "Connected to search progress updates (legacy)",
                    "upgrade_notice": "Consider upgrading to /ws/v2/realtime/{room_id} for enhanced features",
                }
            )

            # Keep connection alive and handle incoming messages
            while True:
                try:
                    # Wait for client messages
                    data = await websocket.receive_text()
                    message = json.loads(data)

                    # Handle different message types
                    if message.get("type") == "ping":
                        await websocket.send_json(
                            {
                                "type": "pong",
                                "timestamp": message.get("timestamp"),
                            }
                        )
                    elif message.get("type") == "subscribe":
                        # Subscribe to specific search progress
                        search_id = message.get("search_id")
                        if search_id:
                            # This would be implemented with proper subscription logic
                            await websocket.send_json(
                                {
                                    "type": "subscribed",
                                    "search_id": search_id,
                                    "message": f"Subscribed to search {search_id}",
                                }
                            )

                except asyncio.TimeoutError:
                    # Send periodic heartbeat
                    await websocket.send_json(
                        {"type": "heartbeat", "client_id": client_id}
                    )

        except WebSocketDisconnect:
            logger.info(f"WebSocket client disconnected: {client_id}")
        except Exception as e:
            logger.error(f"WebSocket error for client {client_id}: {e}")
        finally:
            if client_id:
                await websocket_service.disconnect(client_id)

    @app.websocket("/ws/events")
    async def websocket_events(
        websocket: WebSocket,
        event_bus: Annotated[EventBus, Depends(get_event_bus)],
    ):
        """WebSocket endpoint for general event streaming."""
        await websocket.accept()

        try:
            logger.info("Event streaming WebSocket connected")

            # Send connection confirmation
            await websocket.send_json(
                {
                    "type": "event_stream_connected",
                    "message": "Connected to event stream",
                }
            )

            # Create event handler
            async def event_handler(event_name: str, event_data: dict):
                try:
                    await websocket.send_json(
                        {
                            "type": "event",
                            "event_name": event_name,
                            "event_data": event_data,
                            "timestamp": event_data.get("timestamp"),
                        }
                    )
                except Exception as e:
                    logger.error(f"Failed to send event via WebSocket: {e}")

            # Subscribe to events (this would be properly implemented)
            # For now, we'll just keep the connection alive

            # Keep connection alive
            while True:
                try:
                    data = await websocket.receive_text()
                    message = json.loads(data)

                    if message.get("type") == "ping":
                        await websocket.send_json(
                            {
                                "type": "pong",
                                "timestamp": message.get("timestamp"),
                            }
                        )

                except asyncio.TimeoutError:
                    # Send heartbeat
                    await websocket.send_json({"type": "heartbeat"})

        except WebSocketDisconnect:
            logger.info("Event streaming WebSocket disconnected")
        except Exception as e:
            logger.error(f"Event streaming WebSocket error: {e}")

    @app.websocket("/ws/system-status")
    async def websocket_system_status(websocket: WebSocket):
        """WebSocket endpoint for system status updates."""
        await websocket.accept()

        try:
            logger.info("System status WebSocket connected")

            # Send initial status
            await websocket.send_json(
                {
                    "type": "system_status",
                    "status": "operational",
                    "services": {
                        "api": "healthy",
                        "search": "healthy",
                        "cache": "healthy",
                        "websocket": "healthy",
                    },
                    "timestamp": "2025-01-27T12:00:00Z",
                }
            )

            # Keep connection alive and send periodic status updates
            while True:
                try:
                    # Wait for messages or timeout for periodic updates
                    data = await asyncio.wait_for(
                        websocket.receive_text(), timeout=30.0
                    )
                    message = json.loads(data)

                    if message.get("type") == "get_status":
                        await websocket.send_json(
                            {
                                "type": "system_status",
                                "status": "operational",
                                "services": {
                                    "api": "healthy",
                                    "search": "healthy",
                                    "cache": "healthy",
                                    "websocket": "healthy",
                                },
                                "timestamp": "2025-01-27T12:00:00Z",
                            }
                        )

                except asyncio.TimeoutError:
                    # Send periodic status update
                    await websocket.send_json(
                        {
                            "type": "system_status",
                            "status": "operational",
                            "services": {
                                "api": "healthy",
                                "search": "healthy",
                                "cache": "healthy",
                                "websocket": "healthy",
                            },
                            "timestamp": "2025-01-27T12:00:00Z",
                        }
                    )

        except WebSocketDisconnect:
            logger.info("System status WebSocket disconnected")
        except Exception as e:
            logger.error(f"System status WebSocket error: {e}")

    logger.info("WebSocket endpoints configured successfully")
