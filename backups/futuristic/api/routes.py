"""
API routes for the enhanced interface
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

# Setup logger first
logger = logging.getLogger(__name__)

# Add paths to import the real OmicsOracle pipeline
current_dir = Path(__file__).parent
root_dir = current_dir.parent.parent.parent
sys.path.insert(0, str(root_dir))
sys.path.insert(0, str(root_dir / "src"))

try:
    from omics_oracle.core.config import Config
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
            raise HTTPException(status_code=503, detail=f"Failed to initialize pipeline: {str(e)}")

    return pipeline_instance


def create_api_router(config: EnhancedConfig) -> APIRouter:
    """Create API router with all endpoints"""

    router = APIRouter()

    @router.post("/search")
    async def enhanced_search(request: SearchRequest, background_tasks: BackgroundTasks):
        """Enhanced search using real OmicsOracle pipeline"""

        try:
            if PIPELINE_AVAILABLE:
                # Use real OmicsOracle pipeline
                pipeline = await get_pipeline()

                # Execute search with real NCBI GEO data
                logger.info(f"Searching for: {request.query}")

                pipeline_result = await pipeline.process_query(
                    query=request.query, max_results=request.max_results, include_sra=request.include_sra
                )

                if pipeline_result.is_failed:
                    logger.error(f"Pipeline search failed: {pipeline_result.error}")
                    return {
                        "results": [],
                        "status": "error",
                        "message": f"Search failed: {pipeline_result.error}",
                        "ai_summaries": None,
                    }

                # Convert pipeline results to API format
                search_results = []
                for i, dataset in enumerate(pipeline_result.metadata):
                    search_results.append(
                        SearchResult(
                            id=dataset.get("accession", dataset.get("id", f"dataset_{i}")),
                            title=dataset.get("title", "Unknown Dataset"),
                            description=dataset.get("summary", "No description available"),
                            relevance_score=dataset.get("relevance_score", 0.8),
                            source="NCBI GEO",
                            timestamp=datetime.now().isoformat(),
                            organism=dataset.get("organism"),
                            platform=dataset.get("platform"),
                            sample_count=dataset.get("sample_count"),
                            publication_date=dataset.get("submission_date"),
                        )
                    )

                # Store in history
                search_history.append(
                    {
                        "query": request.query,
                        "timestamp": datetime.now().isoformat(),
                        "results_count": len(search_results),
                        "processing_time": pipeline_result.duration,
                    }
                )

                return {
                    "results": [result.dict() for result in search_results],
                    "status": "success",
                    "query_id": pipeline_result.query_id,
                    "processing_time": pipeline_result.duration,
                    "expanded_query": pipeline_result.expanded_query,
                    "ai_summaries": pipeline_result.ai_summaries,
                    "total_found": len(pipeline_result.metadata),
                }

            else:
                # Fallback to mock results if pipeline not available
                return await _fallback_search(request, config)

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

    async def _fallback_search(request: SearchRequest, config: EnhancedConfig):
        """Fallback search with mock results when pipeline unavailable"""

        await asyncio.sleep(1)  # Simulate processing time

        mock_results = [
            SearchResult(
                id=f"mock_result_{i}",
                title=f"Mock Dataset {i}: {request.query}",
                description=f"This is a mock result for '{request.query}'. Real pipeline not available.",
                relevance_score=round(0.95 - (i * 0.1), 2),
                source="Mock Data",
                timestamp=datetime.now().isoformat(),
                organism="Homo sapiens" if i % 2 == 0 else "Mus musculus",
                platform=f"GPL{1000 + i}",
                sample_count=50 + (i * 10),
                publication_date=f"2023-0{(i % 9) + 1}-01",
            )
            for i in range(min(3, request.max_results))
        ]

        search_history.append(
            {
                "query": request.query,
                "timestamp": datetime.now().isoformat(),
                "results_count": len(mock_results),
            }
        )

        return {
            "results": [result.dict() for result in mock_results],
            "status": "success",
            "message": "Using mock data - real pipeline not available",
        }

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
                "legacy_fallback": "available",
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
