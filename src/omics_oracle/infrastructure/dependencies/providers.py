"""
Dependency providers and container setup.

This module configures the dependency injection container with
all application services and repositories.
"""

import logging

from ...application.use_cases.search_datasets import SearchDatasetsUseCase
from ...domain.repositories.simple_search_repository import (
    SimpleSearchRepository,
)
from ..caching.memory_cache import MemoryCache
from ..configuration.config import get_config
from ..external_apis.geo_client import GEOClient
from ..messaging.event_bus import EventBus
from ..messaging.websocket_service import WebSocketService
from ..repositories.geo_search_repository import GEOSearchRepository
from .container import Container

logger = logging.getLogger(__name__)


async def create_container() -> Container:
    """Create and configure the dependency injection container."""
    container = Container()

    logger.info("Configuring dependency injection container")

    # Configuration
    config = get_config()
    await container.register_singleton(type(config), config)

    # Infrastructure services
    await container.register_singleton(
        MemoryCache, MemoryCache(default_ttl=300)
    )
    await container.register_singleton(EventBus, EventBus())
    await container.register_singleton(WebSocketService, WebSocketService())

    # External API clients
    geo_client = GEOClient(config.geo)
    await container.register_singleton(GEOClient, geo_client)

    # Repositories
    async def create_search_repository() -> SimpleSearchRepository:
        geo_client = await container.get(GEOClient)
        return GEOSearchRepository(geo_client)

    await container.register_factory(
        SimpleSearchRepository, create_search_repository
    )

    # Use cases
    async def create_search_use_case() -> SearchDatasetsUseCase:
        search_repository = await container.get(SimpleSearchRepository)
        event_bus = await container.get(EventBus)
        return SearchDatasetsUseCase(search_repository, event_bus)

    await container.register_factory(
        SearchDatasetsUseCase, create_search_use_case
    )

    logger.info("Dependency injection container configured successfully")

    return container


async def setup_event_subscribers(container: Container) -> None:
    """Set up event subscribers for application events."""
    event_bus = await container.get(EventBus)
    websocket_service = await container.get(WebSocketService)

    # Set up event handlers
    from ..messaging.search_events import (
        SearchCompletedEvent,
        SearchFailedEvent,
        SearchStartedEvent,
    )

    async def handle_search_started(event: SearchStartedEvent):
        """Handle search started events."""
        logger.info(f"Search started: {event.query}")
        # Broadcast to WebSocket clients
        await websocket_service.broadcast(
            {
                "type": "search_started",
                "payload": {
                    "query": event.query,
                    "search_type": event.search_type,
                    "timestamp": event.timestamp.isoformat(),
                },
            }
        )

    async def handle_search_completed(event: SearchCompletedEvent):
        """Handle search completed events."""
        logger.info(
            f"Search completed: {event.query} ({event.results_count} results)"
        )
        # Broadcast to WebSocket clients
        await websocket_service.broadcast(
            {
                "type": "search_completed",
                "payload": {
                    "query": event.query,
                    "results_count": event.results_count,
                    "search_duration": event.search_duration,
                    "timestamp": event.timestamp.isoformat(),
                },
            }
        )

    async def handle_search_failed(event: SearchFailedEvent):
        """Handle search failed events."""
        logger.error(f"Search failed: {event.query} - {event.error_message}")
        # Broadcast to WebSocket clients
        await websocket_service.broadcast(
            {
                "type": "search_failed",
                "payload": {
                    "query": event.query,
                    "error_message": event.error_message,
                    "error_type": event.error_type,
                    "timestamp": event.timestamp.isoformat(),
                },
            }
        )

    # Subscribe to events
    await event_bus.subscribe(SearchStartedEvent, handle_search_started)
    await event_bus.subscribe(SearchCompletedEvent, handle_search_completed)
    await event_bus.subscribe(SearchFailedEvent, handle_search_failed)

    logger.info("Event subscribers configured")
