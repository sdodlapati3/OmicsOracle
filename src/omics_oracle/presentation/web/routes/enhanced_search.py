"""
Enhanced Search API Routes

This module provides enhanced search API routes that integrate with the
AdvancedSearchEnhancer and EnhancedQueryHandler.
"""

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query

from ....search.advanced_search_enhancer import AdvancedSearchEnhancer
from ....search.enhanced_query_handler import EnhancedQueryHandler

logger = logging.getLogger(__name__)

# Create router for enhanced search endpoints
router = APIRouter(tags=["enhanced-search"])

# Initialize the enhanced query handler and search enhancer
query_handler = EnhancedQueryHandler()
search_enhancer = AdvancedSearchEnhancer()


@router.get(
    "/search/enhanced", summary="Enhanced Search with Advanced Features"
)
async def enhanced_search(
    query: str = Query(..., description="The search query"),
    limit: int = Query(20, description="Maximum number of results"),
    trace: bool = Query(False, description="Include trace information"),
) -> Dict[str, Any]:
    """
    Perform an enhanced search with advanced features like semantic ranking,
    result clustering, and query reformulation.

    Args:
        query: The search query
        limit: Maximum number of results to return
        trace: Whether to include query trace information

    Returns:
        Enhanced search results with additional features
    """
    logger.info(
        f"Enhanced search request: query='{query}', limit={limit}, trace={trace}"
    )

    try:
        # Get base search results
        base_results = await query_handler.process_query(
            query, limit=limit, include_trace=trace
        )

        # Apply advanced search features
        results = search_enhancer.add_semantic_ranking(
            base_results.get("results", []), query
        )

        # Apply clustering if there are enough results
        clusters = {}
        if len(results) > 3:
            clusters = search_enhancer.cluster_results(results)

        # Generate query reformulations
        reformulations = search_enhancer.generate_query_reformulations(query)

        # Construct response
        response = {
            "query": query,
            "results": results,
            "total_results": len(results),
            "clusters": clusters,
            "query_reformulations": reformulations,
        }

        # Add trace information if requested
        if trace and "trace" in base_results:
            response["trace"] = base_results["trace"]

        return response

    except Exception as e:
        logger.error(f"Error in enhanced search: {str(e)}")
        raise HTTPException(
            status_code=500, detail=f"Enhanced search error: {str(e)}"
        )


@router.get("/query/components", summary="Extract Query Components")
async def query_components(
    query: str = Query(..., description="The query to analyze"),
) -> Dict[str, Any]:
    """
    Extract biomedical components from a search query.

    Args:
        query: The search query to analyze

    Returns:
        Extracted components from the query
    """
    logger.info(f"Query component extraction request: query='{query}'")

    try:
        # Extract components using the enhanced query handler
        components = query_handler.extract_query_components(query)

        return {
            "query": query,
            "components": components,
            "diseases": [c for c in components if c.get("type") == "disease"],
            "tissues": [c for c in components if c.get("type") == "tissue"],
            "organisms": [c for c in components if c.get("type") == "organism"],
            "data_types": [
                c for c in components if c.get("type") == "data_type"
            ],
        }

    except Exception as e:
        logger.error(f"Error extracting query components: {str(e)}")
        raise HTTPException(
            status_code=500, detail=f"Component extraction error: {str(e)}"
        )
