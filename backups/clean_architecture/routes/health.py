"""
Health check routes.

This module provides health check endpoints for monitoring
system status and readiness.
"""

import asyncio
import logging
from datetime import datetime
from typing import Annotated, Any, Dict

from fastapi import APIRouter, Depends, status

from ....infrastructure.configuration.config import get_config
from ....infrastructure.dependencies.container import Container
from ..dependencies import get_di_container, health_check

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/", response_model=Dict[str, Any])
async def basic_health_check(health_data: Annotated[dict, Depends(health_check)]) -> Dict[str, Any]:
    """Basic health check endpoint."""
    return {
        **health_data,
        "timestamp": datetime.utcnow().isoformat(),
        "checks": {"api": "healthy"},
    }


@router.get("/ready", response_model=Dict[str, Any])
async def readiness_check(container: Annotated[Container, Depends(get_di_container)]) -> Dict[str, Any]:
    """
    Readiness check endpoint.

    Verifies that all required services are available and ready.
    """
    checks = {}
    overall_status = "ready"

    try:
        # Check dependency injection container
        checks["container"] = "ready"

        # Check if we can get core services
        try:
            search_use_case = await container.get_search_use_case()
            checks["search_service"] = "ready" if search_use_case else "not_ready"
        except Exception as e:
            logger.warning(f"Search service check failed: {e}")
            checks["search_service"] = "not_ready"
            overall_status = "not_ready"

        try:
            event_bus = await container.get_event_bus()
            checks["event_bus"] = "ready" if event_bus else "not_ready"
        except Exception as e:
            logger.warning(f"Event bus check failed: {e}")
            checks["event_bus"] = "not_ready"
            overall_status = "not_ready"

        try:
            websocket_service = await container.get_websocket_service()
            checks["websocket_service"] = "ready" if websocket_service else "not_ready"
        except Exception as e:
            logger.warning(f"WebSocket service check failed: {e}")
            checks["websocket_service"] = "not_ready"
            overall_status = "not_ready"

        try:
            cache = await container.get_cache()
            checks["cache"] = "ready" if cache else "not_ready"
        except Exception as e:
            logger.warning(f"Cache check failed: {e}")
            checks["cache"] = "not_ready"
            overall_status = "not_ready"

    except Exception as e:
        logger.error(f"Readiness check failed: {e}")
        overall_status = "not_ready"
        checks["error"] = str(e)

    response_data = {
        "status": overall_status,
        "service": "omics-oracle",
        "version": "3.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "checks": checks,
    }

    # Return appropriate HTTP status code
    status_code = status.HTTP_200_OK if overall_status == "ready" else status.HTTP_503_SERVICE_UNAVAILABLE

    return response_data


@router.get("/live", response_model=Dict[str, Any])
async def liveness_check() -> Dict[str, Any]:
    """
    Liveness check endpoint.

    Simple check to verify the application is running.
    """
    return {
        "status": "alive",
        "service": "omics-oracle",
        "version": "3.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "uptime": "unknown",  # Could be implemented with app start time tracking
    }


@router.get("/config")
async def config_check() -> Dict[str, Any]:
    """
    Configuration check endpoint.

    Returns non-sensitive configuration information.
    """
    config = get_config()

    return {
        "environment": config.environment,
        "debug": config.app.debug,
        "log_level": config.logging.level,
        "geo_api_configured": bool(config.geo.email),
        "cache_enabled": True,  # Since we always have memory cache
        "websocket_enabled": True,
        "monitoring_enabled": config.monitoring.enabled,
    }
