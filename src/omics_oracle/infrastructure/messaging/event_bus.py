"""
Event bus implementation for application events.

Provides a simple in-memory event bus for publishing and subscribing
to domain events.
"""

import asyncio
import logging
from typing import Any, Callable, Dict, List, Type

logger = logging.getLogger(__name__)


class EventBus:
    """Simple in-memory event bus."""

    def __init__(self):
        """Initialize the event bus."""
        self._subscribers: Dict[Type, List[Callable]] = {}
        self._lock = asyncio.Lock()

    async def publish(self, event: Any) -> None:
        """Publish an event to all subscribers."""
        event_type = type(event)

        async with self._lock:
            subscribers = self._subscribers.get(event_type, [])

        if not subscribers:
            logger.debug(f"No subscribers for event: {event_type.__name__}")
            return

        logger.debug(
            f"Publishing event {event_type.__name__} to {len(subscribers)} subscribers"
        )

        # Call all subscribers
        tasks = []
        for subscriber in subscribers:
            try:
                if asyncio.iscoroutinefunction(subscriber):
                    tasks.append(subscriber(event))
                else:
                    # Run sync subscribers in thread pool
                    tasks.append(
                        asyncio.get_event_loop().run_in_executor(
                            None, subscriber, event
                        )
                    )
            except Exception as e:
                logger.error(f"Failed to call subscriber {subscriber}: {e}")

        # Wait for all subscribers to complete
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Log any exceptions
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error(
                        f"Subscriber {subscribers[i]} failed: {result}"
                    )

    async def subscribe(self, event_type: Type, handler: Callable) -> None:
        """Subscribe to an event type."""
        async with self._lock:
            if event_type not in self._subscribers:
                self._subscribers[event_type] = []

            self._subscribers[event_type].append(handler)

        logger.debug(f"Subscribed {handler} to {event_type.__name__}")

    async def unsubscribe(self, event_type: Type, handler: Callable) -> bool:
        """Unsubscribe from an event type."""
        async with self._lock:
            if event_type in self._subscribers:
                try:
                    self._subscribers[event_type].remove(handler)
                    logger.debug(
                        f"Unsubscribed {handler} from {event_type.__name__}"
                    )

                    # Clean up empty subscriber lists
                    if not self._subscribers[event_type]:
                        del self._subscribers[event_type]

                    return True
                except ValueError:
                    pass

        return False

    async def clear(self) -> None:
        """Clear all subscribers."""
        async with self._lock:
            self._subscribers.clear()

        logger.debug("Cleared all event subscribers")

    def get_subscriber_count(self, event_type: Type) -> int:
        """Get the number of subscribers for an event type."""
        return len(self._subscribers.get(event_type, []))

    def get_all_event_types(self) -> List[Type]:
        """Get all subscribed event types."""
        return list(self._subscribers.keys())
