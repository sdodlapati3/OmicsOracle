"""
Search Service Wrapper with Enhanced Error Handling and Progress Reporting

This module wraps the improved_search service to add better error handling
and detailed progress reporting.
"""

import asyncio
import logging
import os
import time
from functools import wraps

# Get the improved search service
from ..services.improved_search import ImprovedSearchService

logger = logging.getLogger(__name__)


def with_retries(max_retries=3, delay=1):
    """Decorator to add retry logic to async functions."""

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            for attempt in range(1, max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_retries:
                        logger.error(f"Failed after {max_retries} attempts: {e}")
                        raise
                    logger.warning(f"Attempt {attempt} failed: {e}. Retrying in {delay}s...")
                    await asyncio.sleep(delay)

        return wrapper

    return decorator


class EnhancedSearchService:
    """Wrapper around the ImprovedSearchService with better error handling and progress reporting."""

    def __init__(self, *args, **kwargs):
        # Log environment for debugging
        ncbi_email = os.environ.get("NCBI_EMAIL")
        logger.info(f"NCBI_EMAIL environment variable: {ncbi_email or 'Not set'}")

        # Initialize the underlying service
        self.service = ImprovedSearchService(*args, **kwargs)

        # Copy any existing attributes
        if hasattr(self.service, "set_progress_callback"):
            self.original_progress_callback = None

    def set_progress_callback(self, callback):
        """Set progress callback with enhanced error handling."""
        self.original_progress_callback = callback

        # Create a wrapped callback that handles errors
        def enhanced_callback(strategy_index, strategy_name, status):
            try:
                callback(strategy_index, strategy_name, status)
                # Log the progress event
                logger.info(f"Progress: Strategy {strategy_index} - {strategy_name} - {status}")
            except Exception as e:
                logger.error(f"Error in progress callback: {e}")

        # Set the callback on the underlying service
        if hasattr(self.service, "set_progress_callback"):
            self.service.set_progress_callback(enhanced_callback)

    @with_retries(max_retries=2, delay=1)
    async def search_with_multiple_strategies(self, query, max_results=10):
        """Perform search with multiple strategies, with retries and better error handling."""
        logger.info(f"EnhancedSearchService: Searching with query: {query}")

        # Check if NCBI email is available
        ncbi_email = os.environ.get("NCBI_EMAIL")
        if not ncbi_email:
            logger.warning("NCBI_EMAIL not set in environment")
            # Try to load from .env file
            try:
                import dotenv

                dotenv.load_dotenv(".env")
                ncbi_email = os.environ.get("NCBI_EMAIL")
                if ncbi_email:
                    logger.info(f"Loaded NCBI_EMAIL from .env: {ncbi_email}")
                else:
                    logger.warning("NCBI_EMAIL not found in .env")
            except ImportError:
                logger.warning("dotenv not available to load .env")

        # Verify the geo_client's email is set
        if hasattr(self.service, "geo_client") and hasattr(self.service.geo_client, "_client"):
            geo_client = self.service.geo_client

            # Try to access email attribute safely
            client_email = getattr(getattr(geo_client, "_client", None), "email", None)
            logger.info(f"GEO client email: {client_email}")

            # If email is not set but we have one in environment, try to set it
            if not client_email and ncbi_email and hasattr(geo_client, "_client"):
                try:
                    geo_client._client.email = ncbi_email
                    logger.info(f"Set GEO client email to: {ncbi_email}")
                except Exception as e:
                    logger.error(f"Could not set GEO client email: {e}")

        try:
            start_time = time.time()
            result = await self.service.search_with_multiple_strategies(query, max_results=max_results)

            # Log performance
            elapsed = time.time() - start_time
            geo_ids, metadata = result
            logger.info(f"Search completed in {elapsed:.2f}s with {len(geo_ids)} results")

            return result
        except Exception as e:
            logger.error(f"Search failed: {e}")

            # Log detailed error information
            if hasattr(self.service, "geo_client"):
                logger.error(f"GEO client info: {self.service.geo_client}")

            # Return empty results instead of failing completely
            logger.warning("Returning empty results due to search error")
            return [], {"error": str(e), "original_query": query}
