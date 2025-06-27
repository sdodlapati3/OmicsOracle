"""
FastAPI dependency injection setup.

This module configures dependency injection for the FastAPI application,
integrating with the Clean Architecture's dependency injection container.
"""

import logging
from typing import Annotated, AsyncGenerator

from fastapi import Depends, FastAPI, HTTPException, Request, status

from ...application.use_cases.enhanced_search_datasets import (
    EnhancedSearchDatasetsUseCase,
)
from ...infrastructure.caching.cache_hierarchy import CacheHierarchy
from ...infrastructure.caching.memory_cache import MemoryCache
from ...infrastructure.configuration.config import AppConfig, get_config
from ...infrastructure.dependencies.container import Container
from ...infrastructure.messaging.event_bus import EventBus
from ...infrastructure.messaging.websocket_service import WebSocketService
from ...infrastructure.microservices.service_discovery import ServiceRegistry
from ...infrastructure.websocket.connection_manager import ConnectionManager
from ...infrastructure.websocket.realtime_service import RealtimeService
from ...infrastructure.websocket.room_manager import RoomManager

logger = logging.getLogger(__name__)


def setup_dependencies(app: FastAPI) -> None:
    """Setup FastAPI dependencies."""
    # Store container in app state for lifespan management
    app.dependency_overrides = {}
    logger.info("FastAPI dependencies configured")


# Configuration dependencies
def get_app_config() -> AppConfig:
    """Get application configuration."""
    return get_config()


# Container dependencies
async def get_di_container(request: Request) -> Container:
    """Get dependency injection container from app state."""
    return request.app.state.container


# Service dependencies
async def get_search_use_case(
    container: Annotated[Container, Depends(get_di_container)]
) -> EnhancedSearchDatasetsUseCase:
    """Get search use case with all dependencies injected."""
    try:
        return await container.get_search_use_case()
    except Exception as e:
        logger.error(f"Failed to get search use case: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Service initialization failed",
        )


async def get_websocket_service(
    container: Annotated[Container, Depends(get_di_container)]
) -> WebSocketService:
    """Get WebSocket service."""
    try:
        return await container.get_websocket_service()
    except Exception as e:
        logger.error(f"Failed to get WebSocket service: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="WebSocket service initialization failed",
        )


async def get_event_bus(
    container: Annotated[Container, Depends(get_di_container)]
) -> EventBus:
    """Get event bus."""
    try:
        return await container.get_event_bus()
    except Exception as e:
        logger.error(f"Failed to get event bus: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Event bus initialization failed",
        )


async def get_cache_service(
    container: Annotated[Container, Depends(get_di_container)]
) -> MemoryCache:
    """Get cache service."""
    try:
        return await container.get_cache()
    except Exception as e:
        logger.error(f"Failed to get cache service: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Cache service initialization failed",
        )


# Health check dependencies
async def health_check() -> dict:
    """Basic health check."""
    return {"status": "healthy", "service": "omics-oracle", "version": "3.0.0"}


# Authentication dependencies (placeholder for future implementation)
async def get_current_user() -> dict:
    """Get current authenticated user (placeholder)."""
    # For now, return anonymous user
    return {"username": "anonymous", "role": "user"}


# Rate limiting dependencies (placeholder for future implementation)
async def rate_limit_check() -> bool:
    """Check rate limiting (placeholder)."""
    # For now, always allow
    return True


# Phase 6 Enhanced Service Dependencies
async def get_connection_manager(
    container: Annotated[Container, Depends(get_di_container)]
) -> ConnectionManager:
    """Get enhanced WebSocket connection manager."""
    try:
        return await container.get(ConnectionManager)
    except Exception as e:
        logger.error(f"Failed to get connection manager: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Connection manager initialization failed",
        )


async def get_room_manager(
    container: Annotated[Container, Depends(get_di_container)]
) -> RoomManager:
    """Get WebSocket room manager."""
    try:
        return await container.get(RoomManager)
    except Exception as e:
        logger.error(f"Failed to get room manager: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Room manager initialization failed",
        )


async def get_realtime_service(
    container: Annotated[Container, Depends(get_di_container)]
) -> RealtimeService:
    """Get real-time service."""
    try:
        return await container.get(RealtimeService)
    except Exception as e:
        logger.error(f"Failed to get real-time service: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Real-time service initialization failed",
        )


async def get_cache_hierarchy(
    container: Annotated[Container, Depends(get_di_container)]
) -> CacheHierarchy:
    """Get multi-level cache hierarchy."""
    try:
        return await container.get(CacheHierarchy)
    except Exception as e:
        logger.error(f"Failed to get cache hierarchy: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Cache hierarchy initialization failed",
        )


async def get_service_registry(
    container: Annotated[Container, Depends(get_di_container)]
) -> ServiceRegistry:
    """Get microservices registry."""
    try:
        return await container.get(ServiceRegistry)
    except Exception as e:
        logger.error(f"Failed to get service registry: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Service registry initialization failed",
        )
