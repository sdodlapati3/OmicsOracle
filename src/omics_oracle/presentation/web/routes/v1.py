"""
Version 1.0 API routes - Legacy compatibility layer.

This module provides backward compatibility for existing API consumers
while implementing the new Clean Architecture patterns.
"""

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse

from ....application.dto.search_dto import SearchRequestDTO, SearchResponseDTO
from ....application.use_cases.enhanced_search_datasets import (
    EnhancedSearchDatasetsUseCase,
)
from ....domain.value_objects.search_query import SearchQuery
from ....infrastructure.dependencies.container import Container
from ..dependencies import get_container

logger = logging.getLogger(__name__)

# Create router for v1 API
router = APIRouter(prefix="/v1", tags=["v1-legacy"])


@router.get("/", summary="V1 API Information")
async def v1_api_info():
    """Get information about the V1 API endpoints."""
    return {
        "version": "1.0.0",
        "status": "stable",
        "description": "Legacy compatibility API for OmicsOracle",
        "endpoints": {
            "search": "/api/v1/search",
            "health": "/api/v1/health",
            "status": "/api/v1/status",
        },
        "documentation": "/docs#tag/v1-legacy",
        "deprecation_notice": "This API version will be deprecated in 6 months. Please migrate to v2.",
    }


@router.get("/search", response_model=SearchResponseDTO)
async def search_datasets_v1(
    query: str = Query(..., description="Search query for GEO datasets"),
    max_results: int = Query(
        10, ge=1, le=100, description="Maximum number of results"
    ),
    organism: Optional[str] = Query(None, description="Filter by organism"),
    study_type: Optional[str] = Query(None, description="Filter by study type"),
    container: Container = Depends(get_container),
) -> SearchResponseDTO:
    """
    Search for GEO datasets (v1.0 compatibility endpoint).

    This endpoint maintains backward compatibility while using the new
    Clean Architecture infrastructure.
    """
    try:
        # Get use case from container
        use_case = await container.get(EnhancedSearchDatasetsUseCase)

        # Create search request
        search_request = SearchRequestDTO(
            query=query,
            max_results=max_results,
            filters={"organism": organism, "study_type": study_type}
            if organism or study_type
            else None,
        )

        # Execute search
        response = await use_case.execute(search_request)

        logger.info(
            f"v1 search completed: {len(response.results)} results for query '{query}'"
        )
        return response

    except Exception as e:
        logger.error(f"v1 search failed: {e}")
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")


@router.get("/health")
async def health_check_v1():
    """Health check endpoint for v1 API."""
    return JSONResponse(
        {
            "status": "healthy",
            "version": "1.0.0",
            "api_version": "v1",
            "message": "OmicsOracle v1 API is operational",
        }
    )


@router.get("/status")
async def get_status_v1():
    """Get system status (v1 compatibility)."""
    return JSONResponse(
        {
            "status": "operational",
            "version": "1.0.0",
            "api_version": "v1",
            "features": {"search": True, "caching": True, "monitoring": True},
        }
    )
