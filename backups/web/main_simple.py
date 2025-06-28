"""
Simplified FastAPI main application for OmicsOracle web interface.

This is a simplified version to get the basic web interface running.
"""

import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

# Add parent directories to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# OmicsOracle imports (after path modification)
from omics_oracle.core.config import Config  # noqa: E402
from omics_oracle.models.analytics import AnalyticsRequest, QueryAnalytics
from omics_oracle.models.analytics import QueryStatus as AnalyticsQueryStatus  # noqa: E402
from omics_oracle.models.analytics import UserPreferences
from omics_oracle.pipeline import ResultFormat  # noqa: E402
from omics_oracle.services.analytics import analytics_service  # noqa: E402
from omics_oracle.web.models import SearchRequest  # noqa: E402

logger = logging.getLogger(__name__)


# WebSocket Connection Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.query_subscribers: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        # Remove from query subscribers
        for query_id, connections in self.query_subscribers.items():
            if websocket in connections:
                connections.remove(websocket)

    async def send_personal_message(self, message: dict, websocket: WebSocket):
        await websocket.send_text(json.dumps(message))

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message))
            except Exception:
                self.disconnect(connection)

    async def send_query_update(self, query_id: str, message: dict):
        if query_id in self.query_subscribers:
            for connection in self.query_subscribers[query_id]:
                try:
                    await connection.send_text(json.dumps(message))
                except Exception:
                    self.disconnect(connection)

    def subscribe_to_query(self, query_id: str, websocket: WebSocket):
        if query_id not in self.query_subscribers:
            self.query_subscribers[query_id] = []
        self.query_subscribers[query_id].append(websocket)


manager = ConnectionManager()

# Create FastAPI application
app = FastAPI(
    title="OmicsOracle Web API",
    description="REST API for OmicsOracle GEO dataset search and analysis",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global variables
config = None
pipeline = None


@app.on_event("startup")
async def startup_event():
    """Initialize application on startup."""
    global config, pipeline

    logger.info("Starting OmicsOracle Web API...")
    try:
        config = Config()
        # Import here to avoid circular imports
        from omics_oracle.pipeline import OmicsOracle  # noqa: E402

        pipeline = OmicsOracle(config)
        logger.info("Pipeline initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize pipeline: {e}")


# Dashboard route
@app.get("/dashboard")
async def analytics_dashboard():
    """Serve the analytics dashboard."""
    return FileResponse("src/omics_oracle/web/static/dashboard.html")


# Enhanced main page route
@app.get("/")
async def main_page():
    """Serve the main web interface."""
    return FileResponse("src/omics_oracle/web/static/index.html")


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "pipeline_initialized": pipeline is not None,
        "config_loaded": config is not None,
    }


@app.get("/api/status")
async def get_system_status():
    """Get system status information."""
    return {
        "status": "healthy",
        "configuration_loaded": config is not None,
        "ncbi_email": config.ncbi.email if config else None,
        "pipeline_initialized": pipeline is not None,
        "active_queries": 0,
    }


@app.post("/api/batch")
async def batch_search(request: dict):
    """Batch processing endpoint for multiple queries."""
    try:
        if not pipeline:
            return JSONResponse(status_code=503, content={"error": "Pipeline not initialized"})

        queries = request.get("queries", [])
        max_results = request.get("max_results", 10)
        include_sra = request.get("include_sra", False)
        output_format = request.get("output_format", "json")

        if not queries or len(queries) == 0:
            return JSONResponse(status_code=400, content={"error": "No queries provided"})

        if len(queries) > 20:
            return JSONResponse(
                status_code=400,
                content={"error": "Maximum 20 queries allowed per batch"},
            )

        # Convert output format string to ResultFormat enum
        try:
            result_format = ResultFormat(output_format.lower())
        except ValueError:
            result_format = ResultFormat.JSON

        logger.info(f"Processing batch of {len(queries)} queries")

        batch_results = []
        for i, query in enumerate(queries):
            try:
                if not query.strip():
                    batch_results.append(
                        {
                            "query": query,
                            "error": "Empty query",
                            "status": "failed",
                        }
                    )
                    continue

                # Process each query through the pipeline
                result = await pipeline.process_query(
                    query=query,
                    max_results=max_results,
                    include_sra=include_sra,
                    result_format=result_format,
                )

                # Convert QueryResult to API response format
                query_response = {
                    "query": query,
                    "query_id": result.query_id,
                    "status": result.status.value,
                    "processing_time": result.duration or 0.0,
                    "entities": _format_entities(result.entities),
                    "metadata": result.metadata,
                }

                if result.is_failed and result.error:
                    query_response["error"] = result.error

                batch_results.append(query_response)

            except Exception as e:
                logger.error(f"Error processing query {i+1}: {e}")
                batch_results.append({"query": query, "error": str(e), "status": "failed"})

        return {
            "batch_id": f"batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "total_queries": len(queries),
            "completed": len([r for r in batch_results if r.get("status") != "failed"]),
            "failed": len([r for r in batch_results if r.get("status") == "failed"]),
            "results": batch_results,
        }

    except Exception as e:
        logger.error(f"Batch processing error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/api/dataset/{dataset_id}")
async def get_dataset_info(dataset_id: str):
    """Get detailed information about a specific GEO dataset."""
    try:
        if not pipeline:
            return JSONResponse(status_code=503, content={"error": "Pipeline not initialized"})

        # Validate dataset ID format
        if not dataset_id.startswith(("GSE", "GDS", "GPL", "GSM")):
            return JSONResponse(
                status_code=400,
                content={"error": "Invalid GEO dataset ID format"},
            )

        logger.info(f"Getting dataset info for: {dataset_id}")

        # For now, search for the specific dataset ID
        result = await pipeline.process_query(
            query=dataset_id,
            max_results=1,
            include_sra=True,
            result_format=ResultFormat.JSON,
        )

        if result.is_failed:
            return JSONResponse(
                status_code=404,
                content={"error": f"Dataset {dataset_id} not found"},
            )

        # Return the first (and hopefully only) result
        if result.metadata:
            dataset_info = result.metadata[0]
            dataset_info.update(
                {
                    "query_id": result.query_id,
                    "processing_time": result.duration or 0.0,
                    "entities": _format_entities(result.entities),
                }
            )
            return dataset_info
        else:
            return JSONResponse(
                status_code=404,
                content={"error": f"No metadata found for {dataset_id}"},
            )

    except Exception as e:
        logger.error(f"Dataset info error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})


# WebSocket endpoint for real-time updates
@app.websocket("/api/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)

            if message.get("action") == "subscribe_query":
                query_id = message.get("query_id")
                if query_id:
                    manager.subscribe_to_query(query_id, websocket)
                    await manager.send_personal_message(
                        {
                            "type": "subscription_confirmed",
                            "query_id": query_id,
                        },
                        websocket,
                    )

            elif message.get("action") == "ping":
                await manager.send_personal_message(
                    {"type": "pong", "timestamp": datetime.now().isoformat()},
                    websocket,
                )

    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        manager.disconnect(websocket)


def _format_entities(entities_dict: dict) -> list:
    """Convert entities dictionary to list format for API response."""
    formatted_entities = []
    for entity_type, entities_list in entities_dict.items():
        for entity in entities_list:
            formatted_entities.append(
                {
                    "text": entity.get("text", ""),
                    "label": entity_type.upper(),
                    "confidence": entity.get("confidence", 0.0),
                }
            )
    return formatted_entities


# Serve static files
static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


# Analytics endpoints
@app.get("/api/analytics/system")
async def get_system_metrics():
    """Get current system performance metrics."""
    try:
        metrics = analytics_service.get_system_metrics()
        return metrics.dict()
    except Exception as e:
        logger.error(f"Error getting system metrics: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": "Unable to retrieve system metrics"},
        )


@app.post("/api/analytics/data")
async def get_analytics_data(request: AnalyticsRequest):
    """Get comprehensive analytics data."""
    try:
        analytics_data = analytics_service.get_analytics_data(
            start_date=request.start_date,
            end_date=request.end_date,
            aggregation=request.aggregation,
        )
        return analytics_data.dict()
    except Exception as e:
        logger.error(f"Error getting analytics data: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": "Unable to retrieve analytics data"},
        )


@app.get("/api/analytics/usage")
async def get_usage_statistics():
    """Get usage statistics for the last 7 days."""
    try:
        usage_stats = analytics_service.get_usage_statistics()
        return usage_stats.dict()
    except Exception as e:
        logger.error(f"Error getting usage statistics: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": "Unable to retrieve usage statistics"},
        )


@app.get("/api/analytics/dashboard")
async def get_dashboard_data():
    """Get data for the analytics dashboard."""
    try:
        # Get current metrics
        system_metrics = analytics_service.get_system_metrics()
        usage_stats = analytics_service.get_usage_statistics()

        # Prepare dashboard data
        dashboard_data = {
            "timestamp": datetime.now().isoformat(),
            "system_health": {
                "status": ("healthy" if system_metrics.pipeline_status else "unhealthy"),
                "total_queries": system_metrics.total_queries,
                "active_queries": system_metrics.active_queries,
                "avg_response_time": system_metrics.average_response_time,
                "error_rate": system_metrics.error_rate,
                "cpu_usage": system_metrics.cpu_usage,
                "memory_usage": system_metrics.memory_usage,
            },
            "usage_overview": {
                "total_queries": usage_stats.total_queries,
                "successful_queries": usage_stats.successful_queries,
                "failed_queries": usage_stats.failed_queries,
                "unique_sessions": usage_stats.unique_sessions,
                "avg_session_queries": usage_stats.avg_session_queries,
            },
            "top_searches": usage_stats.top_search_terms[:10],
            "top_entities": usage_stats.top_entities[:10],
            "trending_datasets": usage_stats.top_datasets[:10],
        }

        return dashboard_data
    except Exception as e:
        logger.error(f"Error getting dashboard data: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": "Unable to retrieve dashboard data"},
        )


# User preferences endpoints
@app.get("/api/preferences/{user_id}")
async def get_user_preferences(user_id: str):
    """Get user preferences."""
    # TODO: Implement user preferences storage
    return JSONResponse(content={"message": "User preferences endpoint - coming soon"})


@app.post("/api/preferences/{user_id}")
async def save_user_preferences(user_id: str, preferences: UserPreferences):
    """Save user preferences."""
    # TODO: Implement user preferences storage
    return JSONResponse(content={"message": "User preferences saved - coming soon"})


# Enhanced search endpoint with analytics
@app.post("/api/search")
async def search_datasets_with_analytics(request: SearchRequest):
    """
    Search for datasets with analytics tracking.
    Real implementation using the OmicsOracle pipeline.
    """
    global pipeline

    if not pipeline:
        await manager.broadcast({"type": "system_error", "message": "Pipeline not initialized"})
        return JSONResponse(status_code=503, content={"error": "Pipeline not initialized"})

    # Generate query ID for tracking
    query_id = f"query_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"

    # Create analytics record
    query_analytics = QueryAnalytics(
        query_id=query_id,
        query_text=request.query,
        query_length=len(request.query),
        max_results=request.max_results,
        include_sra=request.include_sra,
        status=AnalyticsQueryStatus.STARTED,
        processing_time=0.0,  # Will be updated when completed
        user_session_id=None,  # TODO: implement session tracking
        user_agent=None,  # TODO: get from headers
        ip_address=None,  # TODO: get from request
        error_type=None,
        error_message=None,
    )

    # Start analytics tracking
    analytics_service.start_query(query_analytics)

    try:
        # Broadcast query start
        await manager.broadcast(
            {
                "type": "query_started",
                "query_id": query_id,
                "query": request.query,
                "timestamp": datetime.now().isoformat(),
            }
        )

        # Validate query
        if not request.query or len(request.query.strip()) == 0:
            error_msg = "Empty query"
            await manager.broadcast(
                {
                    "type": "query_error",
                    "query_id": query_id,
                    "error": error_msg,
                }
            )

            # Complete analytics tracking
            analytics_service.complete_query(
                query_id,
                AnalyticsQueryStatus.FAILED,
                0.0,
                error_message=error_msg,
            )

            return JSONResponse(
                status_code=400,
                content={
                    "query": request.query,
                    "error": error_msg,
                    "status": "failed",
                },
            )

        # Process the query using the real pipeline
        logger.info(f"Processing search query: {request.query}")

        # Broadcast processing status
        await manager.broadcast(
            {
                "type": "query_processing",
                "query_id": query_id,
                "message": "Processing query with NLP pipeline...",
            }
        )

        start_time = datetime.now()
        result = await pipeline.process_query(
            query=request.query,
            max_results=request.max_results,
            include_sra=request.include_sra,
            result_format=ResultFormat.JSON,
        )
        processing_time = (datetime.now() - start_time).total_seconds()

        # Record dataset access for analytics
        if result.metadata:
            for dataset in result.metadata:
                analytics_service.record_dataset_access(
                    dataset.get("accession", "unknown"),
                    request.query,
                    [
                        e.get("text", "")
                        for entity_list in result.entities.values()
                        for e in entity_list
                        if isinstance(e, dict) and "text" in e
                    ],
                )

        # Complete analytics tracking
        entities_data = []
        for entity_type, entity_list in result.entities.items():
            for entity in entity_list:
                if isinstance(entity, dict):
                    entities_data.append(
                        {
                            "text": entity.get("text", ""),
                            "label": entity.get("label", entity_type),
                            "confidence": entity.get("confidence", 0.0),
                        }
                    )

        analytics_service.complete_query(
            query_id,
            AnalyticsQueryStatus.COMPLETED,
            processing_time,
            results_count=len(result.metadata) if result.metadata else 0,
            entities_extracted=entities_data,
        )

        # Broadcast completion
        count = len(result.metadata) if result.metadata else 0
        await manager.broadcast(
            {
                "type": "query_completed",
                "query_id": query_id,
                "results_count": count,
                "processing_time": processing_time,
            }
        )

        return {
            "query_id": query_id,
            "original_query": request.query,
            "status": "completed",
            "processing_time": processing_time,
            "entities": entities_data,
            "metadata": (
                [
                    {
                        "id": dataset.get("accession", "unknown"),
                        "title": dataset.get("title", ""),
                        "summary": dataset.get("summary", ""),
                        "organism": dataset.get("organism", ""),
                        "platform": dataset.get("platform", ""),
                        "sample_count": dataset.get("sample_count", 0),
                        "publication_date": dataset.get("submission_date", None),
                    }
                    for dataset in result.metadata
                ]
                if result.metadata
                else []
            ),
        }

    except Exception as e:
        error_msg = str(e)
        logger.error(f"Search failed for query '{request.query}': {error_msg}")

        # Complete analytics tracking with error
        analytics_service.complete_query(query_id, AnalyticsQueryStatus.FAILED, 0.0, error_message=error_msg)

        # Broadcast error
        await manager.broadcast({"type": "query_error", "query_id": query_id, "error": error_msg})

        return JSONResponse(
            status_code=500,
            content={
                "query": request.query,
                "error": error_msg,
                "status": "failed",
            },
        )
