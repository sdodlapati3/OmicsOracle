"""
Enhanced Search API Routes

This module provides enhanced search API routes that integrate with the
AdvancedSearchEnhancer and EnhancedQueryHandler.
"""

import logging
from dataclasses import asdict
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Query

from ....pipeline.pipeline import OmicsOracle, ResultFormat
from ....search.advanced_search_enhancer import AdvancedSearchEnhancer
from ....search.enhanced_query_handler import EnhancedQueryHandler

logger = logging.getLogger(__name__)

# Create router for enhanced search endpoints
router = APIRouter(tags=["enhanced-search"])

# Initialize the enhanced query handler and search enhancer
query_handler = EnhancedQueryHandler()
search_enhancer = AdvancedSearchEnhancer()
omics_oracle = OmicsOracle()


@router.get("/search/enhanced", summary="Enhanced Search with Advanced Features")
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
    logger.info(f"Enhanced search request: query='{query}', limit={limit}, trace={trace}")

    try:
        # Use the OmicsOracle pipeline for real enhanced search
        query_result = await omics_oracle.process_query(
            query,
            max_results=limit,
            result_format=ResultFormat.JSON,
        )
        # Convert dataclass to dict for JSON response
        result_dict = asdict(query_result)
        return result_dict

    except Exception as e:
        logger.error(f"Error in enhanced search: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Enhanced search error: {str(e)}")


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
        components = query_handler.extract_components(query)

        return {
            "query": query,
            "components": components,
            "diseases": components.get("diseases", []),
            "tissues": components.get("tissues", []),
            "organisms": components.get("organisms", []),
            "data_types": components.get("data_types", []),
            "analysis_methods": components.get("analysis_methods", []),
        }

    except Exception as e:
        logger.error(f"Error extracting query components: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Component extraction error: {str(e)}")
