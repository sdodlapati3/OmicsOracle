"""
Dependency injection container implementation.

Provides a simple container for managing application dependencies
and their lifetimes.
"""

import asyncio
import logging
from typing import Any, Callable, Dict, Optional, Type, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


class Container:
    """Simple dependency injection container."""

    def __init__(self):
        """Initialize the container."""
        self._singletons: Dict[Type, Any] = {}
        self._factories: Dict[Type, Callable] = {}
        self._instances: Dict[Type, Any] = {}
        self._lock = asyncio.Lock()

    async def register_singleton(self, interface: Type[T], implementation: T) -> None:
        """Register a singleton instance."""
        async with self._lock:
            self._singletons[interface] = implementation
            logger.debug(f"Registered singleton: {interface.__name__}")

    async def register_factory(self, interface: Type[T], factory: Callable[[], T]) -> None:
        """Register a factory function."""
        async with self._lock:
            self._factories[interface] = factory
            logger.debug(f"Registered factory: {interface.__name__}")

    async def register_instance(self, interface: Type[T], instance: T) -> None:
        """Register a specific instance."""
        async with self._lock:
            self._instances[interface] = instance
            logger.debug(f"Registered instance: {interface.__name__}")

    async def get(self, interface: Type[T]) -> T:
        """Get an instance of the requested type."""
        # Check singletons first
        if interface in self._singletons:
            return self._singletons[interface]

        # Check instances
        if interface in self._instances:
            return self._instances[interface]

        # Check factories
        if interface in self._factories:
            factory = self._factories[interface]
            if asyncio.iscoroutinefunction(factory):
                return await factory()
            else:
                return factory()

        raise ValueError(f"No registration found for {interface.__name__}")

    async def get_optional(self, interface: Type[T]) -> Optional[T]:
        """Get an instance if registered, None otherwise."""
        try:
            return await self.get(interface)
        except ValueError:
            return None

    async def clear(self) -> None:
        """Clear all registrations."""
        async with self._lock:
            self._singletons.clear()
            self._factories.clear()
            self._instances.clear()
            logger.debug("Container cleared")

    def is_registered(self, interface: Type) -> bool:
        """Check if a type is registered."""
        return interface in self._singletons or interface in self._factories or interface in self._instances

    async def get_registered_types(self) -> Dict[str, str]:
        """Get information about all registered types."""
        info = {}

        for interface in self._singletons:
            info[interface.__name__] = "singleton"

        for interface in self._factories:
            info[interface.__name__] = "factory"

        for interface in self._instances:
            info[interface.__name__] = "instance"

        return info

    # Service-specific getter methods for presentation layer
    async def get_search_use_case(self):
        """Get enhanced search use case."""
        from ...application.use_cases.enhanced_search_datasets import EnhancedSearchDatasetsUseCase
        from ...infrastructure.configuration.config import get_config
        from ...infrastructure.external_apis.geo_client import GEOClient
        from ...infrastructure.repositories.geo_search_repository import GEOSearchRepository
        from ..messaging.event_bus import EventBus

        # Get or create dependencies
        config = get_config()
        geo_client = GEOClient(config.geo)
        repository = GEOSearchRepository(geo_client)
        event_bus = await self.get_event_bus()

        return EnhancedSearchDatasetsUseCase(repository, event_bus)

    async def get_event_bus(self):
        """Get event bus singleton."""
        from ..messaging.event_bus import EventBus

        if not hasattr(self, "_event_bus"):
            self._event_bus = EventBus()
        return self._event_bus

    async def get_websocket_service(self):
        """Get WebSocket service singleton."""
        from ..messaging.websocket_service import WebSocketService

        if not hasattr(self, "_websocket_service"):
            self._websocket_service = WebSocketService()
        return self._websocket_service

    async def get_cache(self):
        """Get memory cache singleton."""
        from ..caching.memory_cache import MemoryCache

        if not hasattr(self, "_cache"):
            self._cache = MemoryCache(default_ttl=3600)
        return self._cache
