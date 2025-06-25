"""
Query Refinement API Routes for OmicsOracle

This module provides API endpoints for query refinement functionality,
including suggestion generation, similar query lookup, and user feedback collection.
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..services.query_analysis import (
    QueryAnalysisService,
    QuerySuggestion,
    SimilarQuery,
    SuggestionType,
)
from ..web.models import QueryStatus

logger = logging.getLogger(__name__)

# Create router for refinement endpoints
refinement_router = APIRouter(
    prefix="/api/refinement", tags=["Query Refinement"]
)


# Request/Response Models
class QuerySuggestionRequest(BaseModel):
    """Request model for query suggestions."""

    original_query: str = Field(..., description="Original search query")
    result_count: int = Field(..., description="Number of results returned")
    user_session_id: Optional[str] = Field(None, description="User session ID")


class QuerySuggestionResponse(BaseModel):
    """Response model for query suggestions."""

    suggestions: List[Dict] = Field(
        ..., description="List of query suggestions"
    )
    alternative_queries: List[str] = Field(
        default=[], description="Alternative successful queries"
    )
    explanation: str = Field(
        ..., description="Explanation of suggestion generation"
    )
    analysis_metadata: Dict = Field(
        default={}, description="Additional analysis metadata"
    )


class SimilarQueriesRequest(BaseModel):
    """Request model for similar queries."""

    query: str = Field(..., description="Query to find similar queries for")
    limit: int = Field(
        default=5, description="Maximum number of similar queries"
    )


class SimilarQueriesResponse(BaseModel):
    """Response model for similar queries."""

    similar_queries: List[Dict] = Field(
        ..., description="List of similar successful queries"
    )
    success_patterns: List[str] = Field(
        default=[], description="Common success patterns"
    )


class QueryFeedbackRequest(BaseModel):
    """Request model for user feedback on suggestions."""

    original_query: str = Field(..., description="Original query")
    suggested_query: str = Field(
        ..., description="Suggested query that was evaluated"
    )
    user_action: str = Field(..., description="Action taken by user")
    was_helpful: bool = Field(..., description="Whether suggestion was helpful")
    result_improvement: Optional[int] = Field(
        None, description="Improvement in result count"
    )
    user_session_id: Optional[str] = Field(None, description="User session ID")


class QueryFeedbackResponse(BaseModel):
    """Response model for feedback submission."""

    feedback_id: str = Field(..., description="Unique feedback ID")
    status: str = Field(..., description="Feedback processing status")
    message: str = Field(..., description="Response message")


class EnhancedSearchRequest(BaseModel):
    """Request model for enhanced search with refinement."""

    query: str = Field(..., description="Search query")
    max_results: int = Field(
        default=100, description="Maximum results to return"
    )
    include_suggestions: bool = Field(
        default=True, description="Include refinement suggestions"
    )
    user_session_id: Optional[str] = Field(None, description="User session ID")


class EnhancedSearchResponse(BaseModel):
    """Response model for enhanced search."""

    query_id: str = Field(..., description="Unique query ID")
    results: List[Dict] = Field(..., description="Search results")
    refinement_suggestions: Optional[List[Dict]] = Field(
        None, description="Refinement suggestions"
    )
    search_metadata: Dict = Field(
        ..., description="Search metadata and analytics"
    )


# Global service instance (will be initialized with dependencies)
_query_analysis_service: Optional[QueryAnalysisService] = None


def get_query_analysis_service() -> QueryAnalysisService:
    """Dependency to get QueryAnalysisService instance."""
    global _query_analysis_service

    if _query_analysis_service is None:
        # Initialize with NLP components from main pipeline
        try:
            from ..nlp.biomedical_ner import (
                BiomedicalNER,
                EnhancedBiologicalSynonymMapper,
            )

            biomedical_ner = BiomedicalNER()
            synonym_mapper = EnhancedBiologicalSynonymMapper()

            _query_analysis_service = QueryAnalysisService(
                biomedical_ner=biomedical_ner, synonym_mapper=synonym_mapper
            )
            logger.info("QueryAnalysisService initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize QueryAnalysisService: {e}")
            # Create service without NLP components as fallback
            _query_analysis_service = QueryAnalysisService()

    return _query_analysis_service


@refinement_router.post("/suggestions", response_model=QuerySuggestionResponse)
async def get_query_suggestions(
    request: QuerySuggestionRequest,
    analysis_service: QueryAnalysisService = Depends(
        get_query_analysis_service
    ),
):
    """
    Generate refinement suggestions for a query that returned poor results.

    This endpoint analyzes the original query and generates actionable suggestions
    to improve search results, including synonym substitutions, query broadening,
    and structural modifications.
    """
    try:
        logger.info(
            f"Generating suggestions for query: '{request.original_query}'"
        )

        # Analyze the failed query
        analysis = analysis_service.analyze_failed_query(
            query=request.original_query, result_count=request.result_count
        )

        # Generate suggestions based on analysis
        suggestions = analysis_service.generate_suggestions(analysis)

        # Convert suggestions to response format
        suggestion_dicts = []
        for suggestion in suggestions:
            suggestion_dicts.append(
                {
                    "suggested_query": suggestion.suggested_query,
                    "type": suggestion.suggestion_type.value,
                    "confidence": suggestion.confidence_score,
                    "explanation": suggestion.explanation,
                    "expected_results": suggestion.expected_result_count,
                }
            )

        # Find alternative queries
        similar_queries = analysis_service.find_similar_successful_queries(
            request.original_query
        )
        alternative_queries = [sq.query_text for sq in similar_queries]

        # Generate explanation
        issues_found = len(analysis.potential_issues)
        explanation = (
            f"Analyzed query and found {issues_found} potential issues. "
        )
        explanation += (
            f"Generated {len(suggestions)} suggestions to improve results."
        )

        # Prepare analysis metadata
        metadata = {
            "complexity_score": analysis.complexity_score,
            "entities_found": len(analysis.entities_found),
            "issues_identified": [
                issue.value for issue in analysis.potential_issues
            ],
            "processing_time": datetime.utcnow().isoformat(),
        }

        response = QuerySuggestionResponse(
            suggestions=suggestion_dicts,
            alternative_queries=alternative_queries,
            explanation=explanation,
            analysis_metadata=metadata,
        )

        logger.info(f"Generated {len(suggestions)} suggestions for query")
        return response

    except Exception as e:
        logger.error(f"Error generating query suggestions: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate query suggestions: {str(e)}",
        )


@refinement_router.get(
    "/similar-queries", response_model=SimilarQueriesResponse
)
async def get_similar_queries(
    query: str,
    limit: int = 5,
    analysis_service: QueryAnalysisService = Depends(
        get_query_analysis_service
    ),
):
    """
    Find similar queries that returned good results.

    This endpoint searches for queries similar to the input that have
    historically returned successful results, helping users discover
    alternative formulations.
    """
    try:
        logger.info(f"Finding similar queries for: '{query}'")

        if not query.strip():
            raise HTTPException(status_code=400, detail="Query cannot be empty")

        if limit < 1 or limit > 20:
            raise HTTPException(
                status_code=400, detail="Limit must be between 1 and 20"
            )

        # Find similar successful queries
        similar_queries = analysis_service.find_similar_successful_queries(
            query, limit
        )

        # Convert to response format
        similar_query_dicts = []
        for sq in similar_queries:
            similar_query_dicts.append(
                {
                    "query": sq.query_text,
                    "result_count": sq.result_count,
                    "success_score": sq.success_score,
                    "similarity_score": sq.similarity_score,
                    "common_entities": sq.common_entities,
                }
            )

        # Extract success patterns
        success_patterns = []
        if similar_queries:
            # Simple pattern extraction - in production this would be more sophisticated
            success_patterns = [
                "Include specific organism names (human, mouse)",
                "Combine disease terms with assay types",
                "Use general terms before specific ones",
            ]

        response = SimilarQueriesResponse(
            similar_queries=similar_query_dicts,
            success_patterns=success_patterns,
        )

        logger.info(f"Found {len(similar_queries)} similar queries")
        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error finding similar queries: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to find similar queries: {str(e)}"
        )


@refinement_router.post("/feedback", response_model=QueryFeedbackResponse)
async def submit_query_feedback(request: QueryFeedbackRequest):
    """
    Accept user feedback on suggestion effectiveness.

    This endpoint collects user feedback about the quality and helpfulness
    of query refinement suggestions, enabling continuous improvement of
    the suggestion system.
    """
    try:
        logger.info(
            f"Receiving feedback for suggestion: '{request.suggested_query}'"
        )

        # Validate feedback data
        valid_actions = [
            "used_suggestion",
            "modified_suggestion",
            "ignored",
            "dismissed",
        ]
        if request.user_action not in valid_actions:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid user_action. Must be one of: {valid_actions}",
            )

        # Generate feedback ID
        feedback_id = f"feedback_{uuid4().hex[:8]}"

        # Store feedback (in production, this would go to a database)
        feedback_data = {
            "feedback_id": feedback_id,
            "original_query": request.original_query,
            "suggested_query": request.suggested_query,
            "user_action": request.user_action,
            "was_helpful": request.was_helpful,
            "result_improvement": request.result_improvement,
            "user_session_id": request.user_session_id,
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Log feedback for analysis (in production, store in database)
        logger.info(f"Feedback stored: {feedback_data}")

        # Determine response message
        if request.was_helpful:
            message = "Thank you for the positive feedback! This helps improve our suggestions."
        else:
            message = "Thank you for the feedback. We'll use this to improve future suggestions."

        response = QueryFeedbackResponse(
            feedback_id=feedback_id, status="received", message=message
        )

        logger.info(f"Feedback processed successfully: {feedback_id}")
        return response

    except HTTPException as he:
        logger.warning(f"HTTP exception in feedback processing: {he.detail}")
        raise he
    except Exception as e:
        logger.error(f"Error processing feedback: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to process feedback: {str(e)}"
        )


@refinement_router.post(
    "/search/enhanced", response_model=EnhancedSearchResponse
)
async def enhanced_search(
    request: EnhancedSearchRequest,
    analysis_service: QueryAnalysisService = Depends(
        get_query_analysis_service
    ),
):
    """
    Perform search with automatic refinement suggestions.

    This endpoint combines regular search functionality with automatic
    generation of refinement suggestions when results are poor.
    """
    try:
        logger.info(f"Enhanced search for query: '{request.query}'")

        # Generate query ID
        query_id = f"enhanced_{uuid4().hex[:8]}"

        # Import and call the main search pipeline
        try:
            # Import pipeline from main app context
            import sys
            from pathlib import Path

            sys.path.insert(0, str(Path(__file__).parent.parent.parent))
            from omics_oracle.core.config import Config
            from omics_oracle.pipeline import OmicsOracle

            # Get or create pipeline instance
            config = Config()
            pipeline = OmicsOracle(config)

            # Perform the actual search using the same method as main search
            pipeline_result = await pipeline.search_datasets(
                query=request.query,
                max_results=request.max_results,
                include_sra=False,  # Default values for enhanced search
                organism=None,
                assay_type=None,
                date_from=None,
                date_to=None,
            )

            # Extract results from pipeline response
            search_results = pipeline_result.metadata if pipeline_result else []
            result_count = len(search_results)

            logger.info(f"Enhanced search found {result_count} results")

        except Exception as search_error:
            logger.warning(
                f"Main search pipeline failed: {search_error}, using empty results"
            )
            search_results = []
            result_count = 0

        # Initialize response
        response_data = {
            "query_id": query_id,
            "results": search_results,
            "refinement_suggestions": None,
            "search_metadata": {
                "original_query": request.query,
                "result_count": result_count,
                "processing_time": datetime.utcnow().isoformat(),
                "included_suggestions": request.include_suggestions,
            },
        }

        # Generate refinement suggestions if requested and results are poor
        if request.include_suggestions and result_count < 10:
            try:
                analysis = analysis_service.analyze_failed_query(
                    query=request.query, result_count=result_count
                )

                suggestions = analysis_service.generate_suggestions(analysis)

                # Convert suggestions to response format
                suggestion_dicts = []
                for suggestion in suggestions:
                    suggestion_dicts.append(
                        {
                            "suggested_query": suggestion.suggested_query,
                            "type": suggestion.suggestion_type.value,
                            "confidence": suggestion.confidence_score,
                            "explanation": suggestion.explanation,
                        }
                    )

                response_data["refinement_suggestions"] = suggestion_dicts
                response_data["search_metadata"]["suggestions_generated"] = len(
                    suggestions
                )

                logger.info(
                    f"Generated {len(suggestions)} refinement suggestions"
                )

            except Exception as e:
                logger.warning(f"Failed to generate suggestions: {e}")
                response_data["search_metadata"]["suggestion_error"] = str(e)

        response = EnhancedSearchResponse(**response_data)

        logger.info(f"Enhanced search completed: {query_id}")
        return response

    except Exception as e:
        logger.error(f"Enhanced search failed: {e}")
        raise HTTPException(
            status_code=500, detail=f"Enhanced search failed: {str(e)}"
        )


@refinement_router.get("/analytics", response_model=Dict)
async def get_refinement_analytics():
    """
    Get analytics data for query refinement system.

    This endpoint provides metrics about suggestion effectiveness,
    user feedback, and system performance.
    """
    try:
        # In production, this would query actual analytics data
        analytics_data = {
            "total_suggestions_generated": 0,
            "suggestion_acceptance_rate": 0.0,
            "average_result_improvement": 0.0,
            "most_common_suggestion_types": [],
            "user_feedback_summary": {"positive": 0, "negative": 0, "total": 0},
            "system_performance": {
                "average_suggestion_time_ms": 0.0,
                "success_rate": 0.0,
                "error_rate": 0.0,
            },
        }

        logger.info("Analytics data retrieved")
        return analytics_data

    except Exception as e:
        logger.error(f"Error retrieving analytics: {e}")
        raise HTTPException(
            status_code=500, detail=f"Failed to retrieve analytics: {str(e)}"
        )
