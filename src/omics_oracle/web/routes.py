"""
Fixed routes for OmicsOracle web interface with proper data handling.
"""

import logging
import uuid
from datetime import datetime
from typing import List

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect

from .models import (
    AnalyzeRequest,
    BatchRequest,
    DatasetMetadata,
    EntityInfo,
    QueryStatus,
    SearchRequest,
    SearchResult,
    StatusResponse,
    WebSocketMessage,
)

logger = logging.getLogger(__name__)

# Create routers
search_router = APIRouter()
dataset_router = APIRouter()
analysis_router = APIRouter()
batch_router = APIRouter()
config_router = APIRouter()
status_router = APIRouter()
websocket_router = APIRouter()


# Simple function to get pipeline from main module
def get_pipeline_state():
    """Get pipeline and active_queries from main module."""
    try:
        # Import the main module and access global variables directly
        import sys

        main_module = sys.modules.get("src.omics_oracle.web.main")
        if main_module is None:
            # Try alternative import paths
            import src.omics_oracle.web.main as main_module

        pipeline = getattr(main_module, "pipeline", None)
        active_queries = getattr(main_module, "active_queries", {})

        return pipeline, active_queries
    except (ImportError, AttributeError) as e:
        logger.warning("Failed to access pipeline: %s", str(e))
        return None, {}


# WebSocket connection manager
class ConnectionManager:
    """Manages WebSocket connections."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        """Connect a new WebSocket client."""
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        """Disconnect a WebSocket client."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        """Send message to specific client."""
        try:
            await websocket.send_text(message)
        except Exception as e:
            logger.error("Failed to send WebSocket message: %s", str(e))

    async def broadcast(self, message: str):
        """Broadcast message to all connected clients."""
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                logger.error("Failed to send WebSocket message: %s", str(e))
                disconnected.append(connection)

        # Remove disconnected clients
        for conn in disconnected:
            self.disconnect(conn)


manager = ConnectionManager()


@search_router.post("/search", response_model=SearchResult)
async def search_datasets(request: SearchRequest):
    """Search GEO datasets with natural language query."""
    pipeline, active_queries = get_pipeline_state()

    if not pipeline:
        raise HTTPException(status_code=503, detail="Pipeline not initialized")

    # Generate unique query ID
    query_id = f"search_{uuid.uuid4().hex[:8]}"

    # Create initial result
    result = SearchResult(
        query_id=query_id,
        original_query=request.query,
        status=QueryStatus.RUNNING,
        entities=[],
        metadata=[],
    )

    # Store in active queries
    active_queries[query_id] = result

    try:
        # Execute search
        start_time = datetime.utcnow()
        pipeline_result = await pipeline.process_query(
            query=request.query,
            max_results=request.max_results,
            include_sra=request.include_sra,
        )
        end_time = datetime.utcnow()

        # Convert pipeline result to API format
        result.status = QueryStatus.COMPLETED
        result.processing_time = (end_time - start_time).total_seconds()
        result.expanded_query = pipeline_result.expanded_query

        # Convert entities - handle Dict[str, List[Dict[str, Any]]] format
        if pipeline_result.entities:
            for entity_type, entity_list in pipeline_result.entities.items():
                if isinstance(entity_list, list):
                    for entity in entity_list:
                        if isinstance(entity, dict):
                            result.entities.append(
                                EntityInfo(
                                    text=entity.get("text", ""),
                                    label=entity.get("label", entity_type),
                                    confidence=entity.get("confidence"),
                                    start=entity.get("start"),
                                    end=entity.get("end"),
                                )
                            )

        # Convert metadata
        for metadata in pipeline_result.metadata:
            result.metadata.append(
                DatasetMetadata(
                    id=metadata.get("id", ""),
                    title=metadata.get("title", ""),
                    summary=metadata.get("summary", ""),
                    organism=metadata.get("organism"),
                    platform=metadata.get("platform"),
                    sample_count=metadata.get("sample_count"),
                    submission_date=metadata.get("submission_date"),
                    last_update_date=metadata.get("last_update_date"),
                    pubmed_id=metadata.get("pubmed_id"),
                    sra_info=metadata.get("sra_info"),
                )
            )

        # Broadcast update via WebSocket
        try:
            await manager.broadcast(
                WebSocketMessage(
                    type="search_completed",
                    query_id=query_id,
                    data={"results": len(result.metadata)},
                ).json()
            )
        except Exception as ws_error:
            logger.warning("WebSocket broadcast failed: %s", str(ws_error))

    except Exception as e:
        result.status = QueryStatus.FAILED
        result.error_message = str(e)
        logger.error("Search failed for query %s: %s", query_id, str(e))

    finally:
        # Update active queries
        active_queries[query_id] = result

    return result


# Status endpoints
@status_router.get("/status", response_model=StatusResponse)
async def get_status():
    """Get system status."""
    pipeline, active_queries = get_pipeline_state()
    # Get NCBI email from pipeline config if available
    ncbi_email = None
    if pipeline and hasattr(pipeline, "config"):
        ncbi_email = getattr(pipeline.config, "ncbi_email", None)
    return StatusResponse(
        status="healthy" if pipeline else "unhealthy",
        configuration_loaded=pipeline is not None,
        ncbi_email=ncbi_email,
        pipeline_initialized=pipeline is not None,
        active_queries=len(active_queries),
        uptime=None,  # Could add uptime tracking
    )


# Health check (simple endpoint)
@status_router.get("/health")
async def health_check():
    """Simple health check."""
    pipeline, active_queries = get_pipeline_state()
    return {
        "status": "healthy" if pipeline else "unhealthy",
        "pipeline_initialized": pipeline is not None,
        "active_queries": len(active_queries),
    }


# Placeholder endpoints for other functionality
@dataset_router.get("/dataset/{dataset_id}")
async def get_dataset_info(dataset_id: str, include_sra: bool = False):
    """Get detailed information about a specific dataset."""
    return {
        "message": f"Dataset info for {dataset_id}",
        "include_sra": include_sra,
    }


@analysis_router.post("/analyze")
async def analyze_dataset(request: AnalyzeRequest):
    """Analyze a dataset with NLP processing."""
    return {"message": f"Analysis for dataset {request.dataset_id}"}


@batch_router.post("/batch")
async def batch_process(request: BatchRequest):
    """Process multiple queries in batch."""
    return {"message": f"Batch processing {len(request.queries)} queries"}


@config_router.get("/config")
async def get_configuration():
    """Get current configuration."""
    return {"message": "Configuration endpoint"}


# WebSocket endpoint
@websocket_router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates."""
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            message = f"Message received: {data}"
            await manager.send_personal_message(message, websocket)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
