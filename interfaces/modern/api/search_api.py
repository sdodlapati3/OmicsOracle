"""
Search API endpoints for OmicsOracle modern interface
"""

import asyncio

from core.config import get_config
from core.exceptions import SearchException, ValidationException
from core.logging_config import get_api_logger
from flask import Blueprint, jsonify, request
from models import SearchQuery, SearchType, SortField, SortOrder
from services import CacheService, SearchService

# Create blueprint
search_bp = Blueprint("search", __name__)

# Initialize services (these would be dependency injected in a more mature setup)
config = get_config()
search_service = SearchService()
cache_service = CacheService(
    config.CACHE_DIR, config.CACHE_TTL, config.CACHE_ENABLED
)
logger = get_api_logger()


@search_bp.route("/search", methods=["POST"])
def search():
    """
    Perform search operation

    Expected JSON payload:
    {
        "query": "search terms",
        "search_type": "basic|advanced|semantic",
        "page": 1,
        "page_size": 20,
        "sort_field": "relevance|date|title|author|citation_count",
        "sort_order": "asc|desc",
        "filters": {},
        "include_metadata": true
    }
    """
    try:
        # Parse request data
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid JSON payload"}), 400

        # Validate required fields
        if "query" not in data:
            return jsonify({"error": "Missing required field: query"}), 400

        # Create search query object
        search_query = SearchQuery(
            query=data["query"],
            search_type=SearchType(data.get("search_type", "basic")),
            page=int(data.get("page", 1)),
            page_size=int(data.get("page_size", 20)),
            sort_field=SortField(data.get("sort_field", "relevance")),
            sort_order=SortOrder(data.get("sort_order", "desc")),
            filters=data.get("filters", {}),
            include_metadata=data.get("include_metadata", True),
        )

        logger.info(
            f"Search request: {search_query.query} (page: {search_query.page})"
        )

        # Check cache first
        cached_result = cache_service.get_cached_search_result(
            search_query.query, search_query.page, search_query.page_size
        )

        if cached_result:
            logger.debug("Returning cached search result")
            return jsonify(cached_result)

        # Perform search using asyncio to handle the async search service
        search_response = asyncio.run(search_service.search(search_query))

        # Convert to dictionary for JSON response
        response_data = search_response.to_dict()

        # Cache the result
        cache_service.cache_search_result(
            search_query.query,
            search_query.page,
            search_query.page_size,
            response_data,
        )

        return jsonify(response_data)

    except ValidationException as e:
        logger.warning(f"Search validation error: {e.message}")
        return jsonify(e.to_dict()), 400

    except SearchException as e:
        logger.error(f"Search error: {e.message}")
        return jsonify(e.to_dict()), 500

    except ValueError as e:
        logger.warning(f"Search parameter error: {str(e)}")
        return (
            jsonify(
                {
                    "error": "ValidationError",
                    "message": f"Invalid parameter value: {str(e)}",
                }
            ),
            400,
        )

    except Exception as e:
        logger.error(f"Unexpected search error: {str(e)}", exc_info=True)
        return (
            jsonify(
                {
                    "error": "InternalServerError",
                    "message": "An unexpected error occurred",
                }
            ),
            500,
        )


@search_bp.route("/search/suggestions", methods=["GET"])
def get_search_suggestions():
    """
    Get search suggestions based on query prefix

    Query parameters:
    - q: Query prefix
    - limit: Maximum number of suggestions (default: 10)
    """
    try:
        query_prefix = request.args.get("q", "").strip()
        limit = int(request.args.get("limit", 10))

        if not query_prefix:
            return jsonify({"suggestions": []})

        if len(query_prefix) < 2:
            return jsonify({"suggestions": []})

        # TODO: Implement actual suggestion logic
        # This could be based on previous searches, popular terms, etc.
        suggestions = []

        return jsonify(
            {"suggestions": suggestions, "query_prefix": query_prefix}
        )

    except ValueError as e:
        return (
            jsonify(
                {
                    "error": "ValidationError",
                    "message": f"Invalid parameter: {str(e)}",
                }
            ),
            400,
        )

    except Exception as e:
        logger.error(f"Suggestions error: {str(e)}", exc_info=True)
        return (
            jsonify(
                {
                    "error": "InternalServerError",
                    "message": "Failed to get suggestions",
                }
            ),
            500,
        )


@search_bp.route("/search/stats", methods=["GET"])
def get_search_stats():
    """Get search statistics and cache information"""
    try:
        cache_stats = cache_service.get_stats()

        # TODO: Add more search statistics
        stats = {"cache": cache_stats, "search_service": {"status": "active"}}

        return jsonify(stats)

    except Exception as e:
        logger.error(f"Stats error: {str(e)}", exc_info=True)
        return (
            jsonify(
                {
                    "error": "InternalServerError",
                    "message": "Failed to get statistics",
                }
            ),
            500,
        )


@search_bp.route("/search/cache", methods=["DELETE"])
def clear_search_cache():
    """Clear search cache"""
    try:
        success = cache_service.clear()

        if success:
            logger.info("Search cache cleared")
            return jsonify({"message": "Cache cleared successfully"})
        else:
            return jsonify({"error": "Failed to clear cache"}), 500

    except Exception as e:
        logger.error(f"Cache clear error: {str(e)}", exc_info=True)
        return (
            jsonify(
                {
                    "error": "InternalServerError",
                    "message": "Failed to clear cache",
                }
            ),
            500,
        )
