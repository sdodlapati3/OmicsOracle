"""
Search API routes.

This module provides API endpoints for dataset search functionality
using the Clean Architecture use cases.
"""

import logging
import uuid
from typing import Annotated, List

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status

from ....application.dto.search_dto import SearchRequestDTO, SearchResponseDTO
from ....application.use_cases.enhanced_search_datasets import (
    EnhancedSearchDatasetsUseCase,
)
from ....infrastructure.messaging.event_bus import EventBus
from ....infrastructure.messaging.websocket_service import WebSocketService
from ....shared.exceptions.domain_exceptions import DomainError, ValidationError
from ..dependencies import (
    get_event_bus,
    get_search_use_case,
    get_websocket_service,
)

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/datasets", response_model=SearchResponseDTO)
async def search_datasets(
    request: SearchRequestDTO,
    background_tasks: BackgroundTasks,
    search_use_case: Annotated[
        EnhancedSearchDatasetsUseCase, Depends(get_search_use_case)
    ],
    event_bus: Annotated[EventBus, Depends(get_event_bus)],
    websocket_service: Annotated[
        WebSocketService, Depends(get_websocket_service)
    ],
) -> SearchResponseDTO:
    """
    Search for biomedical datasets.

    This endpoint searches for datasets based on the provided query parameters,
    publishes progress events, and returns structured results.
    """
    search_id = str(uuid.uuid4())

    try:
        logger.info(f"Starting dataset search: {search_id}")

        # Execute search use case
        response = await search_use_case.execute(request)

        # Send completion notification via WebSocket
        background_tasks.add_task(
            websocket_service.broadcast,
            {
                "type": "search_completed",
                "search_id": search_id,
                "total_results": response.total_found,
            },
        )

        logger.info(f"Search completed successfully: {search_id}")
        return response

    except ValidationError as e:
        logger.warning(f"Search validation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)
        )
    except DomainError as e:
        logger.error(f"Search domain error: {e}")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e)
        )
    except Exception as e:
        logger.error(f"Search failed: {e}")

        # Send error notification via WebSocket
        background_tasks.add_task(
            websocket_service.broadcast,
            {"type": "search_failed", "search_id": search_id, "error": str(e)},
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Search operation failed",
        )


@router.get("/datasets/{geo_id}")
async def get_dataset_by_id(
    geo_id: str,
    search_use_case: Annotated[
        EnhancedSearchDatasetsUseCase, Depends(get_search_use_case)
    ],
):
    """Get a specific dataset by GEO ID."""
    try:
        # For now, we'll implement a simple search by ID
        # In a full implementation, this would be a separate use case
        request = SearchRequestDTO(
            query=geo_id, max_results=1, search_type="exact_match"
        )

        response = await search_use_case.execute(request)

        if not response.results:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Dataset {geo_id} not found",
            )

        return response.results[0]

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get dataset {geo_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve dataset",
        )


@router.get("/suggestions")
async def get_search_suggestions(query: str, limit: int = 5) -> List[str]:
    """Get search query suggestions."""
    # This is a placeholder implementation
    # In a full system, this would use ML/NLP for intelligent suggestions

    common_terms = [
        "cancer genomics",
        "expression profiling",
        "single cell RNA-seq",
        "microarray analysis",
        "protein expression",
        "metabolomics",
        "proteomics",
        "transcriptomics",
        "biomarker discovery",
        "drug response",
    ]

    # Simple filtering based on query
    suggestions = [
        term for term in common_terms if query.lower() in term.lower()
    ]
    return suggestions[:limit]


@router.get("/stats")
async def get_search_stats():
    """Get search statistics and system status."""
    # This would typically come from monitoring/analytics
    return {
        "total_datasets": "~2.5M",
        "supported_databases": ["GEO", "ArrayExpress", "SRA"],
        "avg_response_time": "1.2s",
        "cache_hit_rate": "85%",
        "system_status": "operational",
    }
