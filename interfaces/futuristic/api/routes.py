"""
API routes for the enhanced interface
"""

import asyncio
import logging
from datetime import datetime
from typing import List

from core.config import AGENT_CONFIG, EnhancedConfig
from fastapi import APIRouter, BackgroundTasks
from pydantic import BaseModel

# Setup logger
logger = logging.getLogger(__name__)


class SearchRequest(BaseModel):
    query: str
    search_type: str = "general"
    filters: dict = None


class SearchResult(BaseModel):
    id: str
    title: str
    description: str
    relevance_score: float
    source: str
    timestamp: str


class AgentStatus(BaseModel):
    name: str
    status: str
    last_activity: str
    capabilities: List[str]


# In-memory storage (would be replaced with proper database)
search_history: List[dict] = []


def create_api_router(config: EnhancedConfig) -> APIRouter:
    """Create API router with all endpoints"""

    router = APIRouter()

    @router.post("/search")
    async def enhanced_search(
        request: SearchRequest, background_tasks: BackgroundTasks
    ):
        """Enhanced search with simulated AI processing"""

        # Simulate processing time
        await asyncio.sleep(1)

        # Generate mock results
        mock_results = [
            SearchResult(
                id=f"result_{i}",
                title=f"Enhanced Result {i}: {request.query}",
                description=f"AI-generated insight for '{request.query}' using advanced analysis.",
                relevance_score=round(0.95 - (i * 0.1), 2),
                source=["PubMed", "GEO", "TCGA", "String-DB"][i % 4],
                timestamp=datetime.now().isoformat(),
            )
            for i in range(min(3, config.max_search_results))
        ]

        # Store in history
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

                data_points = [
                    DataPoint(**point) for point in data.get("points", [])
                ]
                result = await visualization_service.create_scatter_plot(
                    data_points, config
                )
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
                demo_data = visualization_service.generate_demo_data(
                    VisualizationType(viz_type)
                )
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

            return {
                "slow_requests": performance_tracker.get_recent_slow_requests(
                    threshold_ms=1000
                )
            }
        except Exception as e:
            return {"error": str(e)}

    return router
