"""
AI-powered routes for OmicsOracle web interface.

This module provides AI summarization endpoints using the new LLM integration.
"""

import logging
import uuid

from fastapi import APIRou@ai_router.get, "/ai/cache/stats"


async def get_cache_stats():
    """Get cache statistics - FOR DEBUGGING ONLY (cache no longer affects results)."""
    try:
        from ..services.summarizer import SummarizationService

        summarizer = SummarizationService()
        cache_stats = summarizer.cache.get_stats()

        return {
            "status": "success",
            "cache_stats": cache_stats,
            "message": "Cache statistics retrieved (cache no longer used for serving results)",
            "note": "This cache is for debugging/analysis only - all results are now served fresh",
        }tion

# Import our models
from .models import DatasetMetadata, EntityInfo, QueryStatus, SearchResult, SummarizeRequest

logger = logging.getLogger(__name__)

# Create AI router
ai_router = APIRouter()


@ai_router.post("/summarize", response_model=SearchResult)
async def summarize_datasets(request: SummarizeRequest):
    """
    Search GEO datasets and generate AI-powered summaries.

    This endpoint combines dataset search with intelligent summarization using GPT-4.
    """
    try:
        # Import the pipeline from the new integration
        from ..pipeline.pipeline import OmicsOracle

        # Initialize pipeline
        oracle = OmicsOracle()

        try:
            # Generate unique query ID
            query_id = f"ai_summary_{uuid.uuid4().hex[:8]}"

            logger.info(f"Starting AI summarization for query: {request.query}")

            # Process the query through our enhanced pipeline
            pipeline_result = await oracle.search_datasets(
                query=request.query,
                max_results=request.max_results,
                include_sra=False,
                organism=request.organism,
                assay_type=request.assay_type,
                date_from=request.date_from,
                date_to=request.date_to,
            )

            if pipeline_result.is_failed:
                raise HTTPException(
                    status_code=500,
                    detail=f"Pipeline processing failed: {pipeline_result.error}",
                )

            # Convert to web API format
            result = SearchResult(
                query_id=query_id,
                original_query=request.query,
                expanded_query=pipeline_result.expanded_query,
                status=QueryStatus.COMPLETED,
                processing_time=pipeline_result.duration,
                entities=[],
                metadata=[],
                ai_summaries=pipeline_result.ai_summaries,
                error_message=None,
            )

            # Convert entities
            for entity_type, entity_list in pipeline_result.entities.items():
                for entity in entity_list:
                    result.entities.append(
                        EntityInfo(
                            text=entity.get("text", ""),
                            label=entity_type,
                            confidence=entity.get("confidence"),
                            start=entity.get("start"),
                            end=entity.get("end"),
                        )
                    )

            # Convert metadata
            for metadata in pipeline_result.metadata:
                result.metadata.append(
                    DatasetMetadata(
                        id=metadata.get("accession", ""),
                        title=metadata.get("title", ""),
                        summary=metadata.get("summary", ""),
                        organism=metadata.get("organism"),
                        platform=metadata.get("platform"),
                        sample_count=len(metadata.get("samples", [])),
                        submission_date=metadata.get("submission_date"),
                        last_update_date=metadata.get("last_update_date"),
                        pubmed_id=metadata.get("pubmed_id"),
                        sra_info=metadata.get("sra_info"),
                    )
                )

            logger.info(f"AI summarization completed for query: {query_id}")
            return result

        except Exception as e:
            logger.error(f"Error during AI summarization: {e}")
            raise HTTPException(
                status_code=500, detail=f"Summarization failed: {str(e)}"
            )

        finally:
            await oracle.close()

    except Exception as e:
        logger.error(f"AI summarization endpoint error: {e}")
        raise HTTPException(
            status_code=500, detail=f"Internal server error: {str(e)}"
        )


@ai_router.get("/summarize/status/{query_id}")
async def get_summary_status(query_id: str):
    """Get the status of an AI summarization query."""
    # This could be enhanced to track long-running queries
    return {"query_id": query_id, "status": "completed"}


@ai_router.get("/ai/capabilities")
async def get_ai_capabilities():
    """Get information about AI capabilities and configuration."""
    try:
        from ..services.summarizer import SummarizationService

        summarizer = SummarizationService()

        return {
            "llm_available": summarizer.client is not None,
            "model": summarizer.model if summarizer.client else None,
            "summary_types": ["brief", "comprehensive", "technical"],
            "max_tokens": summarizer.max_tokens if summarizer.client else None,
            "ai_service_available": summarizer.client is not None,
        }

    except Exception as e:
        logger.error(f"Error getting AI capabilities: {e}")
        return {"llm_available": False, "error": str(e)}


@ai_router.post("/ai/test")
async def test_ai_integration():
    """Test endpoint to verify AI integration is working."""
    try:
        from ..services.summarizer import SummarizationService

        summarizer = SummarizationService()

        if not summarizer.client:
            return {
                "status": "unavailable",
                "message": "OpenAI client not available, AI summarization unavailable",
            }

        # Test with a small sample
        test_metadata = {
            "accession": "TEST123",
            "title": "Test dataset for AI summarization",
            "summary": "This is a test dataset to verify AI summarization functionality.",
            "organism": "Homo sapiens",
            "platform": "Test Platform",
            "samples": [{"title": "Sample 1"}, {"title": "Sample 2"}],
        }

        test_summary = summarizer.summarize_dataset(
            test_metadata, query_context="test query", summary_type="brief"
        )

        return {
            "status": "success",
            "message": "AI integration is working",
            "test_summary": test_summary,
        }

    except Exception as e:
        logger.error(f"AI test failed: {e}")
        return {"status": "error", "message": f"AI test failed: {str(e)}"}


@ai_router.get("/ai/cache/stats")
async def get_cache_stats():
    """Get AI cache statistics and performance metrics."""
    try:
        from ..services.summarizer import SummarizationService

        summarizer = SummarizationService()
        cache_stats = summarizer.cache.get_stats()

        return {
            "status": "success",
            "cache_stats": cache_stats,
            "message": "Cache statistics retrieved successfully",
        }

    except Exception as e:
        logger.error(f"Error getting cache stats: {e}")
        return {
            "status": "error",
            "message": f"Failed to get cache stats: {str(e)}",
        }


@ai_router.post("/ai/cache/cleanup")
async def cleanup_cache():
    """Clean up expired cache entries - FOR DEBUGGING ONLY (cache no longer affects results)."""
    try:
        from ..services.summarizer import SummarizationService

        summarizer = SummarizationService()
        removed_count = summarizer.cache.cleanup_expired()

        return {
            "status": "success",
            "removed_entries": removed_count,
            "message": f"Cleaned up {removed_count} debugging cache entries (cache no longer affects results)",
            "note": "This cache is for debugging/analysis only - all results are now served fresh",
        }

    except Exception as e:
        logger.error(f"Error cleaning cache: {e}")
        return {
            "status": "error",
            "message": f"Failed to clean cache: {str(e)}",
        }


@ai_router.delete("/ai/cache/clear")
async def clear_cache():
    """Clear all cache entries - FOR DEBUGGING ONLY (cache no longer affects results)."""
    try:
        from ..services.summarizer import SummarizationService

        summarizer = SummarizationService()
        removed_count = summarizer.cache.clear_all()

        return {
            "status": "success",
            "removed_entries": removed_count,
            "message": f"Cleared {removed_count} debugging cache entries (cache no longer affects results)",
            "note": "This cache is for debugging/analysis only - all results are now served fresh",
        }

    except Exception as e:
        logger.error(f"Error clearing cache: {e}")
        return {
            "status": "error",
            "message": f"Failed to clear cache: {str(e)}",
        }
