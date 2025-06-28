"""
Enhanced API routes for the OmicsOracle application.

This module provides enhanced search endpoints with real-time capabilities
and improve                    # Generate AI summary using centralized manager
                    if not dataset_dto.ai_summary and ai_summary_manager:
                        dataset_dto.ai_summary = ai_summary_manager.generate_ai_summary(
                            request.query,
                            dataset_dto.__dict__,
                            dataset_dto.id
                        )erformance for dataset discovery and analysis.
"""

import asyncio
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from core.config import AGENT_CONFIG, EnhancedConfig
from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

# Import centralized AI summary manager
try:
    from src.omics_oracle.services.ai_summary_manager import ai_summary_manager
except ImportError:
    logger.warning("AI Summary Manager not available")
    ai_summary_manager = None

# Setup logger first
logger = logging.getLogger(__name__)

# Add paths to import the real OmicsOracle pipeline
current_dir = Path(__file__).parent
root_dir = current_dir.parent.parent.parent
sys.path.insert(0, str(root_dir))
sys.path.insert(0, str(root_dir / "src"))

try:
    from omics_oracle.application.dto.search_dto import SearchRequestDTO

    # Import enhanced search components
    from omics_oracle.application.use_cases.enhanced_search_datasets import EnhancedSearchDatasetsUseCase
    from omics_oracle.core.config import Config
    from omics_oracle.infrastructure.repositories.geo_search_repository import GeoSearchRepository
    from omics_oracle.pipeline.pipeline import OmicsOracle

    PIPELINE_AVAILABLE = True
    logger.info("OmicsOracle pipeline imports successful")
except ImportError as e:
    logger.warning(f"Could not import OmicsOracle pipeline: {e}")
    PIPELINE_AVAILABLE = False


class SearchRequest(BaseModel):
    query: str
    search_type: str = "enhanced"
    max_results: int = 10
    include_sra: bool = False
    organism: Optional[str] = None
    assay_type: Optional[str] = None
    date_from: Optional[str] = None
    date_to: Optional[str] = None


class SearchResult(BaseModel):
    id: str
    title: str
    description: str
    relevance_score: float
    source: str
    timestamp: str
    organism: Optional[str] = None
    platform: Optional[str] = None
    sample_count: Optional[int] = None
    publication_date: Optional[str] = None
    ai_summary: Optional[str] = None


class AgentStatus(BaseModel):
    name: str
    status: str
    last_activity: str
    capabilities: List[str]


# In-memory storage (would be replaced with proper database)
search_history: List[dict] = []

# Initialize pipeline
pipeline_instance = None


async def get_pipeline():
    """Get or initialize the OmicsOracle pipeline"""
    global pipeline_instance

    if not PIPELINE_AVAILABLE:
        raise HTTPException(status_code=503, detail="OmicsOracle pipeline not available")

    if pipeline_instance is None:
        try:
            config = Config()
            pipeline_instance = OmicsOracle(config)
            logger.info("OmicsOracle pipeline initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize pipeline: {e}")
            raise HTTPException(
                status_code=503,
                detail=f"Failed to initialize pipeline: {str(e)}",
            )

    return pipeline_instance


def create_api_router(config: EnhancedConfig) -> APIRouter:
    """Create API router with all endpoints"""

    router = APIRouter()

    @router.post("/search")
    async def enhanced_search(request: SearchRequest, background_tasks: BackgroundTasks):
        """Enhanced search using improved relevance scoring"""

        try:
            if PIPELINE_AVAILABLE:
                # Use enhanced search use case with better relevance scoring
                logger.info(f"Searching for: {request.query}")

                # Initialize the enhanced search components
                search_repository = GeoSearchRepository()
                search_use_case = EnhancedSearchDatasetsUseCase(search_repository)

                # Create search request DTO
                search_request_dto = SearchRequestDTO(query=request.query, max_results=request.max_results)

                # Execute enhanced search
                search_response = await search_use_case.execute(search_request_dto)

                # Convert response to API format that matches frontend expectations
                results = []
                for dataset_dto in search_response.datasets:
                    # Generate AI summary using centralized manager (single source of truth)
                    if not dataset_dto.ai_summary and ai_summary_manager:
                        dataset_dto.ai_summary = ai_summary_manager.generate_ai_summary(
                            request.query, dataset_dto.__dict__, dataset_dto.geo_id
                        )

                    results.append(
                        {
                            "geo_id": dataset_dto.geo_id,
                            "title": dataset_dto.title,
                            "summary": dataset_dto.summary,  # Original GEO summary
                            "ai_summary": dataset_dto.ai_summary,  # AI-generated summary (None if unavailable)
                            "description": dataset_dto.description,
                            "relevance_score": dataset_dto.relevance_score,
                            "organism": dataset_dto.organism,
                            "platform": dataset_dto.platform,
                            "sample_count": dataset_dto.samples_count,
                            "publication_date": dataset_dto.submission_date,
                        }
                    )

                # Store in history
                search_history.append(
                    {
                        "query": request.query,
                        "timestamp": datetime.now().isoformat(),
                        "results_count": len(results),
                        "processing_time": search_response.search_time,
                    }
                )

                return {
                    "results": results,
                    "status": "success",
                    "query": request.query,
                    "search_time": search_response.search_time,
                    "total_found": search_response.total_found,
                }

            else:
                # No fallback - honest error when pipeline unavailable
                error_message = "OmicsOracle pipeline service unavailable"
                if ai_summary_manager:
                    error_message = ai_summary_manager.get_error_message("Search service")

                return {
                    "results": [],
                    "status": "error",
                    "message": error_message,
                    "ai_summaries": None,
                }

        except Exception as e:
            logger.error(f"Search error: {e}")
            return {
                "results": [],
                "status": "error",
                "message": f"Search error: {str(e)}",
                "ai_summaries": None,
            }

    @router.post("/summarize")
    async def ai_summarize(request: SearchRequest, background_tasks: BackgroundTasks):
        """AI-powered search with enhanced summarization (same as search but explicit)"""
        # This endpoint does the same as search but with AI summaries always enabled
        return await enhanced_search(request, background_tasks)

    @router.get("/agents")
    async def get_agent_status():
        """Get current agent status"""
        agents = []
        for agent_id, info in AGENT_CONFIG.items():
            agents.append(
                AgentStatus(
                    name=info["name"],
                    status=info["status"],
                    last_activity=datetime.now().isoformat(),
                    capabilities=info["capabilities"],
                )
            )
        return {
            "agents": [agent.dict() for agent in agents],
            "total": len(agents),
        }

    @router.get("/health")
    async def health():
        """Health check endpoint"""
        return {
            "status": "healthy",
            "mode": "enhanced",
            "message": "Enhanced futuristic interface running",
            "features": {
                "search": "active",
                "websockets": "active",
                "agents": "simulated",
            },
            "search_history_count": len(search_history),
        }

    @router.get("/stats")
    async def get_stats():
        """Get system statistics"""
        return {
            "uptime": "active",
            "searches_performed": len(search_history),
            "agents_count": len(AGENT_CONFIG),
            "last_search": search_history[-1] if search_history else None,
        }

    @router.post("/visualize")
    async def create_visualization(request: dict):
        """Create a new visualization"""
        try:
            from services.visualization_service import (
                VisualizationConfig,
                VisualizationType,
                visualization_service,
            )

            viz_type = request.get("type", "scatter_plot")
            title = request.get("title", "Untitled Visualization")
            data = request.get("data", {})

            config = VisualizationConfig(
                viz_type=VisualizationType(viz_type),
                title=title,
                width=request.get("width", 800),
                height=request.get("height", 600),
                theme=request.get("theme", "dark"),
            )

            # Route to appropriate visualization method
            if viz_type == "scatter_plot":
                from services.visualization_service import DataPoint

                data_points = [DataPoint(**point) for point in data.get("points", [])]
                result = await visualization_service.create_scatter_plot(data_points, config)
            elif viz_type == "network_graph":
                result = await visualization_service.create_network_graph(
                    data.get("nodes", []), data.get("edges", []), config
                )
            elif viz_type == "heatmap":
                result = await visualization_service.create_heatmap(
                    data.get("matrix", []),
                    data.get("row_labels", []),
                    data.get("col_labels", []),
                    config,
                )
            elif viz_type == "volcano_plot":
                result = await visualization_service.create_volcano_plot(
                    data.get("fold_changes", []),
                    data.get("p_values", []),
                    data.get("gene_names", []),
                    config,
                )
            else:
                # Generate demo data for unsupported types
                demo_data = visualization_service.generate_demo_data(VisualizationType(viz_type))
                result = {
                    "demo": True,
                    "data": demo_data,
                    "message": f"Demo {viz_type} created",
                }

            return {"status": "success", "visualization": result}

        except Exception as e:
            logger.error(f"Visualization creation error: {e}")
            return {"status": "error", "message": str(e)}

    @router.get("/visualizations")
    async def list_visualizations():
        """List all active visualizations"""
        try:
            from services.visualization_service import visualization_service

            return visualization_service.list_visualizations()
        except Exception as e:
            return {"error": str(e)}

    @router.get("/performance")
    async def get_performance_metrics():
        """Get system performance metrics"""
        try:
            from core.performance import performance_tracker

            return {
                "status": "success",
                "metrics": performance_tracker.get_system_metrics(),
                "endpoint_stats": performance_tracker.get_endpoint_stats(),
                "agent_stats": performance_tracker.get_agent_stats(),
            }
        except Exception as e:
            return {"error": str(e)}

    @router.get("/performance/endpoints")
    async def get_endpoint_performance():
        """Get detailed endpoint performance statistics"""
        try:
            from core.performance import performance_tracker

            return performance_tracker.get_endpoint_stats()
        except Exception as e:
            return {"error": str(e)}

    @router.get("/performance/agents")
    async def get_agent_performance():
        """Get agent performance statistics"""
        try:
            from core.performance import performance_tracker

            return performance_tracker.get_agent_stats()
        except Exception as e:
            return {"error": str(e)}

    @router.get("/performance/slow-requests")
    async def get_slow_requests():
        """Get recent slow requests"""
        try:
            from core.performance import performance_tracker

            return {"slow_requests": performance_tracker.get_recent_slow_requests(threshold_ms=1000)}
        except Exception as e:
            return {"error": str(e)}

    return router
