"""
Real-Time Service for Live Search Updates and Progress Tracking
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
from .message_queue import MessagePriority, message_queue
from .room_manager import RoomType, room_manager


class SearchEventType(Enum):
    """Types of search events"""

    SEARCH_STARTED = "search_started"
    SEARCH_PROGRESS = "search_progress"
    SEARCH_RESULT_FOUND = "search_result_found"
    SEARCH_BATCH_COMPLETE = "search_batch_complete"
    SEARCH_ERROR = "search_error"
    SEARCH_COMPLETED = "search_completed"
    SEARCH_CANCELLED = "search_cancelled"


class SearchPhase(Enum):
    """Search process phases"""

    INITIALIZING = "initializing"
    QUERYING_NCBI = "querying_ncbi"
    PROCESSING_RESULTS = "processing_results"
    AI_SUMMARIZATION = "ai_summarization"
    FINALIZING = "finalizing"
    COMPLETED = "completed"
    ERROR = "error"


@dataclass
class SearchProgress:
    """Search progress information"""

    search_id: str
    phase: SearchPhase
    progress_percent: float = 0.0
    current_step: str = ""
    total_steps: int = 0
    completed_steps: int = 0

    # Results tracking
    results_found: int = 0
    results_processed: int = 0

    # Timing
    started_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    estimated_completion: Optional[float] = None

    # Error tracking
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "search_id": self.search_id,
            "phase": self.phase.value,
            "progress_percent": self.progress_percent,
            "current_step": self.current_step,
            "total_steps": self.total_steps,
            "completed_steps": self.completed_steps,
            "results_found": self.results_found,
            "results_processed": self.results_processed,
            "started_at": self.started_at,
            "updated_at": self.updated_at,
            "estimated_completion": self.estimated_completion,
            "errors": self.errors,
            "warnings": self.warnings,
            "metadata": self.metadata,
        }


@dataclass
class SearchSession:
    """Active search session"""

    search_id: str
    user_id: Optional[str]
    query: str
    room_id: str
    progress: SearchProgress

    # Connection tracking
    connections: Set[str] = field(default_factory=set)

    # State
    is_active: bool = True
    created_at: float = field(default_factory=time.time)

    # Callbacks
    progress_callbacks: List[Callable] = field(default_factory=list)
    completion_callbacks: List[Callable] = field(default_factory=list)
    error_callbacks: List[Callable] = field(default_factory=list)


class RealtimeService:
    """
    Real-time service for live search updates and progress tracking
    """

    def __init__(self):
        # Active search sessions
        self._search_sessions: Dict[str, SearchSession] = {}
        self._user_searches: Dict[str, Set[str]] = {}  # user_id -> search_ids

        # Event subscribers
        self._event_subscribers: Dict[SearchEventType, List[Callable]] = {
            event_type: [] for event_type in SearchEventType
        }

        # Global subscribers (receive all events)
        self._global_subscribers: List[Callable] = []

        # Performance tracking
        self._performance_metrics: Dict[str, Any] = {
            "active_searches": 0,
            "total_searches": 0,
            "events_sent": 0,
            "average_search_duration": 0.0,
            "search_completion_rate": 0.0,
        }

        self.logger = logging.getLogger(__name__)

    async def start(self):
        """Start the real-time service"""
        self.logger.info("Starting real-time service")

        # Subscribe to connection manager events
        connection_manager.add_disconnection_callback(
            self._handle_connection_disconnect
        )

        # Subscribe to room manager events
        room_manager.add_user_left_callback(self._handle_user_left_room)

        self.logger.info("Real-time service started")

    async def stop(self):
        """Stop the real-time service"""
        self.logger.info("Stopping real-time service")

        # Cancel all active searches
        search_ids = list(self._search_sessions.keys())
        for search_id in search_ids:
            await self.cancel_search(search_id, "Service shutdown")

        self.logger.info("Real-time service stopped")

    async def start_search(
        self,
        search_id: str,
        user_id: Optional[str],
        query: str,
        connection_id: Optional[str] = None,
    ) -> str:
        """
        Start a new search session with real-time tracking
        """
        # Create or get search room
        room_id = await room_manager.get_or_create_search_room(
            search_id, user_id
        )

        # Initialize progress
        progress = SearchProgress(
            search_id=search_id,
            phase=SearchPhase.INITIALIZING,
            current_step="Initializing search session",
        )

        # Create search session
        search_session = SearchSession(
            search_id=search_id,
            user_id=user_id,
            query=query,
            room_id=room_id,
            progress=progress,
        )

        # Store session
        self._search_sessions[search_id] = search_session

        # Track user searches
        if user_id:
            if user_id not in self._user_searches:
                self._user_searches[user_id] = set()
            self._user_searches[user_id].add(search_id)

        # Join connection to search room
        if connection_id:
            await self.join_search(search_id, connection_id)

        # Update metrics
        self._performance_metrics["active_searches"] = len(
            self._search_sessions
        )
        self._performance_metrics["total_searches"] += 1

        # Send initial event
        await self._send_search_event(
            search_id,
            SearchEventType.SEARCH_STARTED,
            {
                "query": query,
                "search_id": search_id,
                "progress": progress.to_dict(),
            },
        )

        self.logger.info(f"Search started: {search_id} for user {user_id}")
        return room_id

    async def join_search(self, search_id: str, connection_id: str) -> bool:
        """
        Join a connection to an active search session
        """
        if search_id not in self._search_sessions:
            return False

        search_session = self._search_sessions[search_id]

        # Join room
        success = await room_manager.join_room(
            connection_id, search_session.room_id
        )

        if success:
            search_session.connections.add(connection_id)

            # Send current progress to new connection
            progress_message = WebSocketMessage(
                type=MessageType.SEARCH_PROGRESS,
                data={
                    "event_type": SearchEventType.SEARCH_PROGRESS.value,
                    "progress": search_session.progress.to_dict(),
                },
            )

            await message_queue.enqueue_to_connection(
                connection_id, progress_message, priority=MessagePriority.HIGH
            )

            self.logger.info(
                f"Connection {connection_id} joined search {search_id}"
            )

        return success

    async def leave_search(self, search_id: str, connection_id: str) -> bool:
        """
        Remove a connection from a search session
        """
        if search_id not in self._search_sessions:
            return False

        search_session = self._search_sessions[search_id]

        # Leave room
        success = await room_manager.leave_room(
            connection_id, search_session.room_id
        )

        if success:
            search_session.connections.discard(connection_id)
            self.logger.info(
                f"Connection {connection_id} left search {search_id}"
            )

        return success

    async def update_search_progress(
        self,
        search_id: str,
        phase: Optional[SearchPhase] = None,
        progress_percent: Optional[float] = None,
        current_step: Optional[str] = None,
        completed_steps: Optional[int] = None,
        total_steps: Optional[int] = None,
        results_found: Optional[int] = None,
        results_processed: Optional[int] = None,
        estimated_completion: Optional[float] = None,
        **metadata,
    ):
        """
        Update search progress and notify subscribers
        """
        if search_id not in self._search_sessions:
            self.logger.warning(f"Search session not found: {search_id}")
            return

        search_session = self._search_sessions[search_id]
        progress = search_session.progress

        # Update progress fields
        if phase is not None:
            progress.phase = phase
        if progress_percent is not None:
            progress.progress_percent = progress_percent
        if current_step is not None:
            progress.current_step = current_step
        if completed_steps is not None:
            progress.completed_steps = completed_steps
        if total_steps is not None:
            progress.total_steps = total_steps
        if results_found is not None:
            progress.results_found = results_found
        if results_processed is not None:
            progress.results_processed = results_processed
        if estimated_completion is not None:
            progress.estimated_completion = estimated_completion

        # Update metadata
        progress.metadata.update(metadata)
        progress.updated_at = time.time()

        # Auto-calculate progress if possible
        if progress.total_steps > 0 and progress_percent is None:
            progress.progress_percent = (
                progress.completed_steps / progress.total_steps
            ) * 100

        # Send progress update
        await self._send_search_event(
            search_id,
            SearchEventType.SEARCH_PROGRESS,
            {"progress": progress.to_dict(), "metadata": metadata},
        )

        self.logger.debug(
            f"Search progress updated: {search_id} - {progress.progress_percent:.1f}%"
        )

    async def add_search_result(
        self,
        search_id: str,
        result_data: Dict[str, Any],
        result_index: Optional[int] = None,
    ):
        """
        Add a new search result and notify subscribers
        """
        if search_id not in self._search_sessions:
            return

        search_session = self._search_sessions[search_id]

        # Update result count
        search_session.progress.results_found += 1
        search_session.progress.updated_at = time.time()

        # Send result event
        await self._send_search_event(
            search_id,
            SearchEventType.SEARCH_RESULT_FOUND,
            {
                "result": result_data,
                "result_index": result_index,
                "total_results": search_session.progress.results_found,
            },
        )

        self.logger.debug(
            f"Search result added: {search_id} - {search_session.progress.results_found} results"
        )

    async def add_search_error(
        self,
        search_id: str,
        error_message: str,
        error_type: str = "general",
        is_fatal: bool = False,
    ):
        """
        Add a search error and notify subscribers
        """
        if search_id not in self._search_sessions:
            return

        search_session = self._search_sessions[search_id]

        # Add error to progress
        search_session.progress.errors.append(error_message)
        search_session.progress.updated_at = time.time()

        # If fatal error, mark as error phase
        if is_fatal:
            search_session.progress.phase = SearchPhase.ERROR
            search_session.is_active = False

        # Send error event
        await self._send_search_event(
            search_id,
            SearchEventType.SEARCH_ERROR,
            {
                "error_message": error_message,
                "error_type": error_type,
                "is_fatal": is_fatal,
                "total_errors": len(search_session.progress.errors),
            },
            priority=MessagePriority.HIGH,
        )

        self.logger.warning(f"Search error: {search_id} - {error_message}")

    async def add_search_warning(self, search_id: str, warning_message: str):
        """
        Add a search warning
        """
        if search_id not in self._search_sessions:
            return

        search_session = self._search_sessions[search_id]

        # Add warning to progress
        search_session.progress.warnings.append(warning_message)
        search_session.progress.updated_at = time.time()

        self.logger.info(f"Search warning: {search_id} - {warning_message}")

    async def complete_search(
        self,
        search_id: str,
        final_results: Optional[Dict[str, Any]] = None,
        summary: Optional[str] = None,
    ):
        """
        Complete a search session
        """
        if search_id not in self._search_sessions:
            return

        search_session = self._search_sessions[search_id]

        # Update progress
        search_session.progress.phase = SearchPhase.COMPLETED
        search_session.progress.progress_percent = 100.0
        search_session.progress.current_step = "Search completed"
        search_session.progress.updated_at = time.time()
        search_session.is_active = False

        # Send completion event
        await self._send_search_event(
            search_id,
            SearchEventType.SEARCH_COMPLETED,
            {
                "final_results": final_results,
                "summary": summary,
                "duration": time.time() - search_session.progress.started_at,
                "total_results": search_session.progress.results_found,
                "progress": search_session.progress.to_dict(),
            },
            priority=MessagePriority.HIGH,
        )

        # Call completion callbacks
        for callback in search_session.completion_callbacks:
            try:
                await callback(search_session, final_results)
            except Exception as e:
                self.logger.error(f"Completion callback error: {e}")

        # Update metrics
        duration = time.time() - search_session.progress.started_at
        self._update_completion_metrics(
            duration, len(search_session.progress.errors) == 0
        )

        # Schedule session cleanup
        asyncio.create_task(
            self._cleanup_search_session(search_id, delay=300)
        )  # 5 minutes

        self.logger.info(
            f"Search completed: {search_id} - {search_session.progress.results_found} results"
        )

    async def cancel_search(
        self, search_id: str, reason: str = "User cancelled"
    ):
        """
        Cancel an active search session
        """
        if search_id not in self._search_sessions:
            return

        search_session = self._search_sessions[search_id]

        # Update progress
        search_session.progress.current_step = f"Search cancelled: {reason}"
        search_session.progress.updated_at = time.time()
        search_session.is_active = False

        # Send cancellation event
        await self._send_search_event(
            search_id,
            SearchEventType.SEARCH_CANCELLED,
            {"reason": reason, "progress": search_session.progress.to_dict()},
        )

        # Cleanup immediately
        await self._cleanup_search_session(search_id)

        self.logger.info(f"Search cancelled: {search_id} - {reason}")

    async def _send_search_event(
        self,
        search_id: str,
        event_type: SearchEventType,
        data: Dict[str, Any],
        priority: MessagePriority = MessagePriority.NORMAL,
    ):
        """
        Send search event to all subscribers
        """
        if search_id not in self._search_sessions:
            return

        search_session = self._search_sessions[search_id]

        # Create event message
        event_data = {
            "event_type": event_type.value,
            "search_id": search_id,
            "timestamp": time.time(),
            **data,
        }

        # Create WebSocket message
        message = WebSocketMessage(
            type=MessageType.SEARCH_PROGRESS
            if event_type == SearchEventType.SEARCH_PROGRESS
            else MessageType.SEARCH_RESULT,
            data=event_data,
            room_id=search_session.room_id,
        )

        # Send to search room
        await message_queue.enqueue_to_room(
            search_session.room_id, message, priority=priority
        )

        # Call event-specific callbacks
        callbacks = self._event_subscribers.get(event_type, [])
        for callback in callbacks:
            try:
                await callback(search_session, event_data)
            except Exception as e:
                self.logger.error(f"Event callback error: {e}")

        # Call global callbacks
        for callback in self._global_subscribers:
            try:
                await callback(event_type, search_session, event_data)
            except Exception as e:
                self.logger.error(f"Global callback error: {e}")

        # Update metrics
        self._performance_metrics["events_sent"] += 1

    async def _cleanup_search_session(self, search_id: str, delay: int = 0):
        """
        Clean up search session resources
        """
        if delay > 0:
            await asyncio.sleep(delay)

        if search_id not in self._search_sessions:
            return

        search_session = self._search_sessions[search_id]

        # Remove from user searches
        if (
            search_session.user_id
            and search_session.user_id in self._user_searches
        ):
            self._user_searches[search_session.user_id].discard(search_id)
            if not self._user_searches[search_session.user_id]:
                del self._user_searches[search_session.user_id]

        # Destroy search room (if auto-cleanup is enabled)
        room_info = room_manager.get_room_info(search_session.room_id)
        if room_info and room_info.auto_cleanup:
            await room_manager.destroy_room(
                search_session.room_id, "Search session ended"
            )

        # Remove session
        del self._search_sessions[search_id]

        # Update metrics
        self._performance_metrics["active_searches"] = len(
            self._search_sessions
        )

        self.logger.debug(f"Search session cleaned up: {search_id}")

    async def _handle_connection_disconnect(
        self, connection_id: str, connection_info, reason: str
    ):
        """Handle connection disconnection"""
        # Remove connection from all search sessions
        for search_session in self._search_sessions.values():
            search_session.connections.discard(connection_id)

    async def _handle_user_left_room(
        self, connection_id: str, room_id: str, user_id: Optional[str]
    ):
        """Handle user leaving a room"""
        # Find search sessions using this room
        for search_session in self._search_sessions.values():
            if search_session.room_id == room_id:
                search_session.connections.discard(connection_id)

    def _update_completion_metrics(self, duration: float, success: bool):
        """Update completion metrics"""
        # Update average duration
        current_avg = self._performance_metrics["average_search_duration"]
        total_searches = self._performance_metrics["total_searches"]

        if total_searches > 1:
            new_avg = (
                (current_avg * (total_searches - 1)) + duration
            ) / total_searches
        else:
            new_avg = duration

        self._performance_metrics["average_search_duration"] = new_avg

        # Update completion rate (simple implementation)
        if success:
            current_rate = self._performance_metrics["search_completion_rate"]
            new_rate = (
                (current_rate * (total_searches - 1)) + 1.0
            ) / total_searches
            self._performance_metrics["search_completion_rate"] = new_rate

    # Subscription management
    def subscribe_to_event(
        self, event_type: SearchEventType, callback: Callable
    ):
        """Subscribe to specific search events"""
        self._event_subscribers[event_type].append(callback)

    def subscribe_to_all_events(self, callback: Callable):
        """Subscribe to all search events"""
        self._global_subscribers.append(callback)

    def add_search_callback(
        self, search_id: str, callback_type: str, callback: Callable
    ):
        """Add callback to specific search session"""
        if search_id not in self._search_sessions:
            return False

        search_session = self._search_sessions[search_id]

        if callback_type == "progress":
            search_session.progress_callbacks.append(callback)
        elif callback_type == "completion":
            search_session.completion_callbacks.append(callback)
        elif callback_type == "error":
            search_session.error_callbacks.append(callback)

        return True

    # Information getters
    def get_search_session(self, search_id: str) -> Optional[SearchSession]:
        """Get search session information"""
        return self._search_sessions.get(search_id)

    def get_user_searches(self, user_id: str) -> List[SearchSession]:
        """Get all active searches for a user"""
        if user_id not in self._user_searches:
            return []

        return [
            self._search_sessions[search_id]
            for search_id in self._user_searches[user_id]
            if search_id in self._search_sessions
        ]

    def get_active_searches(self) -> List[SearchSession]:
        """Get all active search sessions"""
        return [
            session
            for session in self._search_sessions.values()
            if session.is_active
        ]

    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics"""
        return self._performance_metrics.copy()

    def get_search_statistics(self) -> Dict[str, Any]:
        """Get search statistics"""
        active_searches = len(
            [s for s in self._search_sessions.values() if s.is_active]
        )

        phase_counts = {}
        for session in self._search_sessions.values():
            phase = session.progress.phase.value
            phase_counts[phase] = phase_counts.get(phase, 0) + 1

        return {
            "total_sessions": len(self._search_sessions),
            "active_sessions": active_searches,
            "completed_sessions": len(self._search_sessions) - active_searches,
            "phase_distribution": phase_counts,
            "total_connections": sum(
                len(s.connections) for s in self._search_sessions.values()
            ),
            **self._performance_metrics,
        }


# Global real-time service instance
realtime_service = RealtimeService()
