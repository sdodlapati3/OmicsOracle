"""
Version 2.0 API routes - Advanced features and enhanced capabilities.

This module provides the latest API features including real-time updates,
advanced caching, microservices integration, and enhanced analytics.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

from ....application.dto.search_dto import SearchRequestDTO, SearchResponseDTO
from ....application.use_cases.enhanced_search_datasets import EnhancedSearchDatasetsUseCase
from ....domain.value_objects.search_query import SearchQuery
from ....infrastructure.caching.cache_hierarchy import CacheHierarchy
from ....infrastructure.dependencies.container import Container
from ....infrastructure.microservices.service_discovery import ServiceRegistry
from ....infrastructure.websocket.realtime_service import RealtimeService
from ..dependencies import get_di_container

logger = logging.getLogger(__name__)

# Create router for v2 API
router = APIRouter(prefix="/v2", tags=["v2-advanced"])


@router.get("/", summary="V2 API Information")
async def v2_api_info():
    """Get information about the V2 API endpoints."""
    return {
        "version": "2.0.0",
        "status": "active",
        "description": "Advanced API with real-time features and enhanced capabilities",
        "endpoints": {
            "advanced_search": "/api/v2/search/advanced",
            "cache_stats": "/api/v2/cache/stats",
            "services": "/api/v2/services/registry",
            "health": "/api/v2/health/detailed",
        },
        "features": [
            "real-time-updates",
            "advanced-caching",
            "microservices-ready",
            "websocket-support",
        ],
        "documentation": "/docs#tag/v2-advanced",
        "websockets": {
            "realtime_search": "/api/v2/realtime/search/{search_id}",
            "system_events": "/ws/events",
            "progress": "/ws/search-progress",
        },
    }


@router.get("/search/advanced", response_model=SearchResponseDTO)
async def advanced_search_v2(
    query: str = Query(..., description="Advanced search query with semantic understanding"),
    max_results: int = Query(20, ge=1, le=200, description="Maximum number of results"),
    organism: Optional[str] = Query(None, description="Filter by organism"),
    study_type: Optional[str] = Query(None, description="Filter by study type"),
    date_range: Optional[str] = Query(None, description="Filter by date range (YYYY-MM-DD:YYYY-MM-DD)"),
    include_metadata: bool = Query(True, description="Include comprehensive metadata"),
    enable_caching: bool = Query(True, description="Enable multi-level caching"),
    realtime_updates: bool = Query(False, description="Enable real-time progress updates"),
    container: Container = Depends(get_di_container),
) -> SearchResponseDTO:
    """
    Advanced search with enhanced features (v2.0).

    Features:
    - Semantic query understanding
    - Multi-level caching
    - Real-time progress updates
    - Enhanced metadata extraction
    - Advanced filtering options
    """
    try:
        # Get services from container
        use_case = await container.get(EnhancedSearchDatasetsUseCase)
        cache_hierarchy = await container.get(CacheHierarchy)
        realtime_service = await container.get(RealtimeService)

        # Parse date range if provided
        date_filter = None
        if date_range:
            try:
                start_date, end_date = date_range.split(":")
                date_filter = {"start": start_date, "end": end_date}
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid date range format")

        # Create enhanced search request
        search_request = SearchRequestDTO(
            query=query,
            max_results=max_results,
            filters={
                "organism": organism,
                "study_type": study_type,
                "date_range": date_filter,
            },
            options={
                "include_metadata": include_metadata,
                "enable_caching": enable_caching,
                "realtime_updates": realtime_updates,
                "semantic_search": True,
            },
        )

        # Execute search with progress tracking
        if realtime_updates:
            # Start async progress tracking
            search_id = f"search_{hash(query)}_{hash(str(search_request))}"
            asyncio.create_task(realtime_service.track_search_progress(search_id, search_request))

        response = await use_case.execute(search_request)

        # Add v2-specific metadata
        response.metadata = response.metadata or {}
        response.metadata.update(
            {
                "api_version": "2.0.0",
                "features_used": {
                    "semantic_search": True,
                    "caching": enable_caching,
                    "realtime_updates": realtime_updates,
                    "enhanced_metadata": include_metadata,
                },
                "performance": {
                    "cache_hit_rate": getattr(cache_hierarchy, "hit_rate", 0.0),
                    "total_cache_levels": 3,
                },
            }
        )

        logger.info(f"v2 advanced search completed: {len(response.datasets)} results")
        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"v2 advanced search failed: {e}")
        raise HTTPException(status_code=500, detail=f"Advanced search failed: {str(e)}")


@router.get("/cache/stats")
async def get_cache_stats_v2(container: Container = Depends(get_di_container)):
    """Get comprehensive cache statistics (v2 feature)."""
    try:
        cache_hierarchy = await container.get(CacheHierarchy)

        # Get stats from each cache level, awaiting if necessary
        l1_stats = {}
        l2_stats = {}
        l3_stats = {}

        if hasattr(cache_hierarchy.l1_cache, "get_stats"):
            l1_result = cache_hierarchy.l1_cache.get_stats()
            l1_stats = await l1_result if hasattr(l1_result, "__await__") else l1_result

        if hasattr(cache_hierarchy.l2_cache, "get_stats"):
            l2_result = cache_hierarchy.l2_cache.get_stats()
            l2_stats = await l2_result if hasattr(l2_result, "__await__") else l2_result

        if hasattr(cache_hierarchy.l3_cache, "get_stats"):
            l3_result = cache_hierarchy.l3_cache.get_stats()
            l3_stats = await l3_result if hasattr(l3_result, "__await__") else l3_result

        stats = {
            "cache_levels": {
                "L1_memory": l1_stats,
                "L2_redis": l2_stats,
                "L3_file": l3_stats,
            },
            "hierarchy_stats": {
                "total_hits": getattr(cache_hierarchy, "total_hits", 0),
                "total_misses": getattr(cache_hierarchy, "total_misses", 0),
                "hit_rate": getattr(cache_hierarchy, "hit_rate", 0.0),
                "promotion_count": getattr(cache_hierarchy, "promotion_count", 0),
                "demotion_count": getattr(cache_hierarchy, "demotion_count", 0),
            },
        }

        return JSONResponse(stats)

    except Exception as e:
        logger.error(f"Failed to get cache stats: {e}")
        raise HTTPException(status_code=500, detail=f"Cache stats unavailable: {str(e)}")


@router.get("/services/registry")
async def get_service_registry_v2(
    container: Container = Depends(get_di_container),
):
    """Get microservices registry status (v2 feature)."""
    try:
        service_registry = await container.get(ServiceRegistry)

        services = service_registry.list_services()
        registry_stats = {
            "total_services": len(services),
            "healthy_services": len(
                [s for s in services if s.status == "healthy" or getattr(s, "healthy", False)]
            ),
            "services": [
                {
                    "id": s.service_id,
                    "name": s.name,
                    "type": s.service_type.value if hasattr(s.service_type, "value") else str(s.service_type),
                    "url": s.url,
                    "status": s.status.value if hasattr(s.status, "value") else str(s.status),
                    "version": getattr(s, "version", "unknown"),
                    "last_seen": getattr(s, "last_seen", None),
                }
                for s in services
            ],
        }

        return JSONResponse(registry_stats)

    except Exception as e:
        logger.error(f"Failed to get service registry: {e}")
        raise HTTPException(status_code=500, detail=f"Service registry unavailable: {str(e)}")


@router.websocket("/realtime/search/{search_id}")
async def websocket_search_updates_v2(
    websocket: WebSocket,
    search_id: str,
    container: Container = Depends(get_di_container),
):
    """
    WebSocket endpoint for real-time search progress updates (v2 feature).
    """
    await websocket.accept()

    try:
        realtime_service = await container.get(RealtimeService)

        # Subscribe to search updates
        async def update_handler(update: Dict[str, Any]):
            await websocket.send_json(update)

        await realtime_service.subscribe_to_search(search_id, update_handler)

        # Keep connection alive
        try:
            while True:
                await websocket.receive_text()  # Keep connection alive
        except WebSocketDisconnect:
            logger.info(f"WebSocket disconnected for search {search_id}")

    except Exception as e:
        logger.error(f"WebSocket error for search {search_id}: {e}")
        await websocket.close(code=1011, reason=f"Internal error: {str(e)}")


@router.get("/health/detailed")
async def detailed_health_check_v2(
    container: Container = Depends(get_di_container),
):
    """Comprehensive health check with service dependencies (v2 feature)."""
    try:
        # Check all major services
        health_status = {
            "api_version": "2.0.0",
            "overall_status": "healthy",
            "services": {},
            "features": {
                "caching": {"enabled": True, "status": "operational"},
                "websockets": {"enabled": True, "status": "operational"},
                "microservices": {"enabled": True, "status": "operational"},
                "realtime": {"enabled": True, "status": "operational"},
            },
        }

        # Test cache hierarchy
        try:
            cache_hierarchy = await container.get(CacheHierarchy)
            await cache_hierarchy.get("__health_check__")
            health_status["services"]["cache"] = {
                "status": "healthy",
                "response_time": "< 1ms",
            }
        except Exception as e:
            health_status["services"]["cache"] = {
                "status": "degraded",
                "error": str(e),
            }
            health_status["overall_status"] = "degraded"

        # Test service registry
        try:
            service_registry = await container.get(ServiceRegistry)
            services = service_registry.list_services()
            health_status["services"]["registry"] = {
                "status": "healthy",
                "service_count": len(services),
            }
        except Exception as e:
            health_status["services"]["registry"] = {
                "status": "degraded",
                "error": str(e),
            }
            health_status["overall_status"] = "degraded"

        return JSONResponse(health_status)

    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            {
                "api_version": "2.0.0",
                "overall_status": "unhealthy",
                "error": str(e),
            },
            status_code=503,
        )


# Import and include the enhanced search router
from .enhanced_search import router as enhanced_search_router

# Include the enhanced search router
router.include_router(enhanced_search_router, prefix="")
