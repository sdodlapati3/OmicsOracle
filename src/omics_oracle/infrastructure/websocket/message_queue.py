"""
Message Queue System for Reliable WebSocket Message Delivery
"""

import asyncio
import json
import logging
import pickle
import time
import uuid
from collections import deque
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

from .connection_manager import MessageType, WebSocketMessage


class MessagePriority(Enum):
    """Message priority levels"""

    LOW = 1
    NORMAL = 2
    HIGH = 3
    URGENT = 4
    CRITICAL = 5


class MessageStatus(Enum):
    """Message delivery status"""

    PENDING = "pending"
    PROCESSING = "processing"
    DELIVERED = "delivered"
    FAILED = "failed"
    EXPIRED = "expired"
    RETRYING = "retrying"


@dataclass
class QueuedMessage:
    """Queued message with metadata"""

    message_id: str
    message: WebSocketMessage
    target_type: str  # "connection", "user", "room", "broadcast"
    target_id: Optional[str] = None
    priority: MessagePriority = MessagePriority.NORMAL
    status: MessageStatus = MessageStatus.PENDING

    # Timing
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    last_attempt: Optional[float] = None

    # Retry logic
    retry_count: int = 0
    max_retries: int = 3
    retry_delay: float = 1.0

    # Callbacks
    success_callback: Optional[Callable] = None
    failure_callback: Optional[Callable] = None

    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.expires_at is None:
            self.expires_at = self.created_at + 3600  # 1 hour default TTL

    def is_expired(self) -> bool:
        """Check if message has expired"""
        return time.time() > self.expires_at

    def should_retry(self) -> bool:
        """Check if message should be retried"""
        return (
            self.retry_count < self.max_retries
            and not self.is_expired()
            and self.status in [MessageStatus.FAILED, MessageStatus.RETRYING]
        )

    def get_next_retry_time(self) -> float:
        """Calculate next retry time with exponential backoff"""
        if not self.last_attempt:
            return time.time()

        backoff = self.retry_delay * (2**self.retry_count)
        return self.last_attempt + backoff

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        return {
            "message_id": self.message_id,
            "message": self.message.to_dict(),
            "target_type": self.target_type,
            "target_id": self.target_id,
            "priority": self.priority.value,
            "status": self.status.value,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "last_attempt": self.last_attempt,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "retry_delay": self.retry_delay,
            "metadata": self.metadata,
        }


class MessageQueue:
    """
    Advanced message queue with priority handling and persistence
    """

    def __init__(
        self,
        max_queue_size: int = 10000,
        persist_to_disk: bool = True,
        queue_file: Optional[str] = None,
        worker_count: int = 3,
    ):
        self.max_queue_size = max_queue_size
        self.persist_to_disk = persist_to_disk
        self.worker_count = worker_count

        # Queue storage by priority
        self._queues: Dict[MessagePriority, deque] = {
            priority: deque() for priority in MessagePriority
        }

        # Message tracking
        self._pending_messages: Dict[str, QueuedMessage] = {}
        self._processing_messages: Dict[str, QueuedMessage] = {}
        self._message_history: List[QueuedMessage] = []

        # Queue file for persistence
        if queue_file:
            self.queue_file = Path(queue_file)
        else:
            self.queue_file = Path("data/message_queue.pkl")

        # Worker management
        self._workers: List[asyncio.Task] = []
        self._worker_semaphore = asyncio.Semaphore(worker_count)
        self._shutdown_event = asyncio.Event()

        # Metrics and monitoring
        self.stats = {
            "messages_queued": 0,
            "messages_processed": 0,
            "messages_delivered": 0,
            "messages_failed": 0,
            "messages_expired": 0,
            "messages_retried": 0,
            "queue_size": 0,
            "processing_count": 0,
        }

        # Callbacks
        self._delivery_callbacks: List[Callable] = []
        self._failure_callbacks: List[Callable] = []

        self.logger = logging.getLogger(__name__)

    async def start(self):
        """Start the message queue"""
        self.logger.info("Starting message queue")

        # Create data directory
        self.queue_file.parent.mkdir(exist_ok=True)

        # Load persisted messages
        await self._load_from_disk()

        # Start worker tasks
        for i in range(self.worker_count):
            worker = asyncio.create_task(self._worker(f"worker-{i}"))
            self._workers.append(worker)

        # Start maintenance task
        self._maintenance_task = asyncio.create_task(self._maintenance())

        self.logger.info(
            f"Message queue started with {self.worker_count} workers"
        )

    async def stop(self):
        """Stop the message queue"""
        self.logger.info("Stopping message queue")

        # Signal shutdown
        self._shutdown_event.set()

        # Wait for workers to finish
        if self._workers:
            await asyncio.gather(*self._workers, return_exceptions=True)

        # Cancel maintenance task
        if hasattr(self, "_maintenance_task"):
            self._maintenance_task.cancel()

        # Persist remaining messages
        if self.persist_to_disk:
            await self._save_to_disk()

        self.logger.info("Message queue stopped")

    async def enqueue(
        self,
        message: WebSocketMessage,
        target_type: str,
        target_id: Optional[str] = None,
        priority: MessagePriority = MessagePriority.NORMAL,
        expires_in: Optional[float] = None,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        success_callback: Optional[Callable] = None,
        failure_callback: Optional[Callable] = None,
        **metadata,
    ) -> str:
        """
        Enqueue a message for delivery
        """
        # Check queue size
        total_queue_size = sum(len(queue) for queue in self._queues.values())
        if total_queue_size >= self.max_queue_size:
            raise Exception(f"Queue is full (max: {self.max_queue_size})")

        # Create queued message
        expires_at = None
        if expires_in:
            expires_at = time.time() + expires_in

        queued_message = QueuedMessage(
            message_id=str(uuid.uuid4()),
            message=message,
            target_type=target_type,
            target_id=target_id,
            priority=priority,
            expires_at=expires_at,
            max_retries=max_retries,
            retry_delay=retry_delay,
            success_callback=success_callback,
            failure_callback=failure_callback,
            metadata=metadata,
        )

        # Add to appropriate queue
        self._queues[priority].append(queued_message)
        self._pending_messages[queued_message.message_id] = queued_message

        # Update statistics
        self.stats["messages_queued"] += 1
        self.stats["queue_size"] = total_queue_size + 1

        self.logger.debug(
            f"Message queued: {queued_message.message_id} ({target_type}:{target_id})"
        )
        return queued_message.message_id

    async def enqueue_to_connection(
        self, connection_id: str, message: WebSocketMessage, **kwargs
    ) -> str:
        """Enqueue message for specific connection"""
        return await self.enqueue(
            message=message,
            target_type="connection",
            target_id=connection_id,
            **kwargs,
        )

    async def enqueue_to_user(
        self, user_id: str, message: WebSocketMessage, **kwargs
    ) -> str:
        """Enqueue message for specific user"""
        return await self.enqueue(
            message=message, target_type="user", target_id=user_id, **kwargs
        )

    async def enqueue_to_room(
        self, room_id: str, message: WebSocketMessage, **kwargs
    ) -> str:
        """Enqueue message for specific room"""
        return await self.enqueue(
            message=message, target_type="room", target_id=room_id, **kwargs
        )

    async def enqueue_broadcast(
        self, message: WebSocketMessage, **kwargs
    ) -> str:
        """Enqueue broadcast message"""
        return await self.enqueue(
            message=message, target_type="broadcast", target_id=None, **kwargs
        )

    async def _worker(self, worker_name: str):
        """
        Worker coroutine to process messages from queue
        """
        self.logger.info(f"Message queue worker started: {worker_name}")

        while not self._shutdown_event.is_set():
            try:
                # Get next message
                queued_message = await self._get_next_message()

                if not queued_message:
                    # No messages available, wait a bit
                    await asyncio.sleep(0.1)
                    continue

                # Process message
                async with self._worker_semaphore:
                    await self._process_message(queued_message)

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Worker {worker_name} error: {e}")
                await asyncio.sleep(1)

        self.logger.info(f"Message queue worker stopped: {worker_name}")

    async def _get_next_message(self) -> Optional[QueuedMessage]:
        """
        Get next message from queue based on priority
        """
        # Check in priority order (highest first)
        for priority in sorted(
            MessagePriority, key=lambda x: x.value, reverse=True
        ):
            queue = self._queues[priority]

            while queue:
                queued_message = queue.popleft()

                # Check if message has expired
                if queued_message.is_expired():
                    await self._handle_expired_message(queued_message)
                    continue

                # Check if it's time to retry
                if (
                    queued_message.status == MessageStatus.RETRYING
                    and time.time() < queued_message.get_next_retry_time()
                ):
                    # Put back at end of queue
                    queue.append(queued_message)
                    continue

                return queued_message

        return None

    async def _process_message(self, queued_message: QueuedMessage):
        """
        Process a single message
        """
        from .connection_manager import connection_manager
        from .room_manager import room_manager

        # Mark as processing
        queued_message.status = MessageStatus.PROCESSING
        queued_message.last_attempt = time.time()
        self._processing_messages[queued_message.message_id] = queued_message

        if queued_message.message_id in self._pending_messages:
            del self._pending_messages[queued_message.message_id]

        self.stats["messages_processed"] += 1
        self.stats["processing_count"] = len(self._processing_messages)

        try:
            success = False

            # Route message based on target type
            if queued_message.target_type == "connection":
                success = await connection_manager.send_message(
                    queued_message.target_id, queued_message.message
                )

            elif queued_message.target_type == "user":
                await connection_manager.send_to_user(
                    queued_message.target_id, queued_message.message
                )
                success = True

            elif queued_message.target_type == "room":
                count = await room_manager.send_to_room(
                    queued_message.target_id, queued_message.message
                )
                success = count > 0

            elif queued_message.target_type == "broadcast":
                await connection_manager.broadcast(queued_message.message)
                success = True

            # Handle result
            if success:
                await self._handle_successful_delivery(queued_message)
            else:
                await self._handle_failed_delivery(queued_message)

        except Exception as e:
            self.logger.error(
                f"Error processing message {queued_message.message_id}: {e}"
            )
            await self._handle_failed_delivery(queued_message)

        finally:
            # Remove from processing
            if queued_message.message_id in self._processing_messages:
                del self._processing_messages[queued_message.message_id]

            self.stats["processing_count"] = len(self._processing_messages)

    async def _handle_successful_delivery(self, queued_message: QueuedMessage):
        """Handle successful message delivery"""
        queued_message.status = MessageStatus.DELIVERED

        # Add to history
        self._message_history.append(queued_message)

        # Limit history size
        if len(self._message_history) > 1000:
            self._message_history = self._message_history[-1000:]

        # Update statistics
        self.stats["messages_delivered"] += 1

        # Call success callback
        if queued_message.success_callback:
            try:
                await queued_message.success_callback(queued_message)
            except Exception as e:
                self.logger.error(f"Success callback error: {e}")

        # Call global delivery callbacks
        for callback in self._delivery_callbacks:
            try:
                await callback(queued_message)
            except Exception as e:
                self.logger.error(f"Delivery callback error: {e}")

        self.logger.debug(f"Message delivered: {queued_message.message_id}")

    async def _handle_failed_delivery(self, queued_message: QueuedMessage):
        """Handle failed message delivery"""
        if queued_message.should_retry():
            # Retry message
            queued_message.status = MessageStatus.RETRYING
            queued_message.retry_count += 1

            # Put back in queue
            self._queues[queued_message.priority].append(queued_message)
            self._pending_messages[queued_message.message_id] = queued_message

            self.stats["messages_retried"] += 1

            self.logger.debug(
                f"Message retry {queued_message.retry_count}/{queued_message.max_retries}: {queued_message.message_id}"
            )

        else:
            # Mark as failed
            queued_message.status = MessageStatus.FAILED

            # Add to history
            self._message_history.append(queued_message)

            # Update statistics
            self.stats["messages_failed"] += 1

            # Call failure callback
            if queued_message.failure_callback:
                try:
                    await queued_message.failure_callback(queued_message)
                except Exception as e:
                    self.logger.error(f"Failure callback error: {e}")

            # Call global failure callbacks
            for callback in self._failure_callbacks:
                try:
                    await callback(queued_message)
                except Exception as e:
                    self.logger.error(f"Failure callback error: {e}")

            self.logger.warning(
                f"Message failed permanently: {queued_message.message_id}"
            )

    async def _handle_expired_message(self, queued_message: QueuedMessage):
        """Handle expired message"""
        queued_message.status = MessageStatus.EXPIRED

        # Add to history
        self._message_history.append(queued_message)

        # Update statistics
        self.stats["messages_expired"] += 1

        self.logger.debug(f"Message expired: {queued_message.message_id}")

    async def _maintenance(self):
        """
        Periodic maintenance tasks
        """
        while not self._shutdown_event.is_set():
            try:
                # Clean up old history
                cutoff_time = time.time() - 86400  # 24 hours
                self._message_history = [
                    msg
                    for msg in self._message_history
                    if msg.created_at > cutoff_time
                ]

                # Save to disk periodically
                if self.persist_to_disk:
                    await self._save_to_disk()

                # Update queue size statistics
                total_queue_size = sum(
                    len(queue) for queue in self._queues.values()
                )
                self.stats["queue_size"] = total_queue_size

                await asyncio.sleep(300)  # Run every 5 minutes

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Maintenance error: {e}")
                await asyncio.sleep(300)

    async def _save_to_disk(self):
        """Save queue state to disk"""
        try:
            # Collect all messages
            all_messages = []

            # From queues
            for queue in self._queues.values():
                all_messages.extend(queue)

            # From processing
            all_messages.extend(self._processing_messages.values())

            # Serialize to file
            data = {
                "messages": [msg.to_dict() for msg in all_messages],
                "stats": self.stats,
                "timestamp": time.time(),
            }

            with open(self.queue_file, "wb") as f:
                pickle.dump(data, f)

            self.logger.debug(f"Queue state saved to {self.queue_file}")

        except Exception as e:
            self.logger.error(f"Error saving queue to disk: {e}")

    async def _load_from_disk(self):
        """Load queue state from disk"""
        if not self.queue_file.exists():
            return

        try:
            with open(self.queue_file, "rb") as f:
                data = pickle.load(f)

            # Restore messages
            for msg_data in data.get("messages", []):
                # Recreate message objects
                message = WebSocketMessage(
                    type=MessageType(msg_data["message"]["type"]),
                    data=msg_data["message"]["data"],
                    timestamp=msg_data["message"]["timestamp"],
                    message_id=msg_data["message"]["message_id"],
                    room_id=msg_data["message"].get("room_id"),
                )

                queued_message = QueuedMessage(
                    message_id=msg_data["message_id"],
                    message=message,
                    target_type=msg_data["target_type"],
                    target_id=msg_data["target_id"],
                    priority=MessagePriority(msg_data["priority"]),
                    status=MessageStatus(msg_data["status"]),
                    created_at=msg_data["created_at"],
                    expires_at=msg_data["expires_at"],
                    last_attempt=msg_data["last_attempt"],
                    retry_count=msg_data["retry_count"],
                    max_retries=msg_data["max_retries"],
                    retry_delay=msg_data["retry_delay"],
                    metadata=msg_data["metadata"],
                )

                # Skip expired messages
                if queued_message.is_expired():
                    continue

                # Add to appropriate queue or processing
                if queued_message.status == MessageStatus.PROCESSING:
                    self._processing_messages[
                        queued_message.message_id
                    ] = queued_message
                else:
                    self._queues[queued_message.priority].append(queued_message)
                    self._pending_messages[
                        queued_message.message_id
                    ] = queued_message

            # Restore statistics
            if "stats" in data:
                self.stats.update(data["stats"])

            self.logger.info(f"Queue state loaded from {self.queue_file}")

        except Exception as e:
            self.logger.error(f"Error loading queue from disk: {e}")

    # Callback management
    def add_delivery_callback(self, callback: Callable):
        """Add callback for successful deliveries"""
        self._delivery_callbacks.append(callback)

    def add_failure_callback(self, callback: Callable):
        """Add callback for failed deliveries"""
        self._failure_callbacks.append(callback)

    # Information getters
    def get_message_status(self, message_id: str) -> Optional[MessageStatus]:
        """Get status of a specific message"""
        # Check pending
        if message_id in self._pending_messages:
            return self._pending_messages[message_id].status

        # Check processing
        if message_id in self._processing_messages:
            return self._processing_messages[message_id].status

        # Check history
        for msg in reversed(self._message_history):
            if msg.message_id == message_id:
                return msg.status

        return None

    def get_queue_statistics(self) -> Dict[str, Any]:
        """Get queue statistics"""
        queue_sizes = {
            priority.name: len(queue)
            for priority, queue in self._queues.items()
        }

        return {
            **self.stats,
            "queue_sizes_by_priority": queue_sizes,
            "pending_count": len(self._pending_messages),
            "history_count": len(self._message_history),
        }

    def get_pending_messages(self, limit: int = 100) -> List[QueuedMessage]:
        """Get list of pending messages"""
        return list(self._pending_messages.values())[:limit]

    def get_processing_messages(self) -> List[QueuedMessage]:
        """Get list of messages currently being processed"""
        return list(self._processing_messages.values())


# Global message queue instance
message_queue = MessageQueue()
