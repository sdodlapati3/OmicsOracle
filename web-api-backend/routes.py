"""
API routes for the OmicsOracle web interface.

This module defines all FastAPI routes and WebSocket endpoints.
"""

import json
import logging
import uuid
from datetime import datetime
from typing import Dict, List

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect

from .models import (
    AISummary,
    AnalyzeRequest,
    BatchAISummary,
    BatchRequest,
    BatchResult,
    ConfigResponse,
    DatasetMetadata,
    EntityInfo,
    QueryStatus,
    SearchRequest,
    SearchResult,
    SearchResultResponse,
    StatusResponse,
    SummarizeRequest,
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
        self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        """Send message to specific client."""
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        """Broadcast message to all connected clients."""
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                logger.error(f"Failed to send WebSocket message: {e}")


manager = ConnectionManager()


# Search endpoints
def validate_search_input(request: SearchRequest):
    """Validate search request input for security."""
    import re

    # Basic input sanitization
    if not request.query or len(request.query.strip()) == 0:
        raise HTTPException(status_code=400, detail="Query cannot be empty")

    if len(request.query) > 1000:
        raise HTTPException(
            status_code=400, detail="Query too long (max 1000 characters)"
        )

    # Check for potential SQL injection patterns
    sql_patterns = [
        r"('|(\\')|(\\\\')|(;|\s;))",
        r"((union)|(select)|(insert)|(update)|(delete)|(drop)|(create)|(alter))\s",
        r"(script|javascript|vbscript|onload|onerror)",
    ]

    query_lower = request.query.lower()
    for pattern in sql_patterns:
        if re.search(pattern, query_lower):
            raise HTTPException(
                status_code=400, detail="Invalid characters detected in query"
            )

    # Validate max_results range
    if request.max_results and (
        request.max_results < 1 or request.max_results > 1000
    ):
        raise HTTPException(
            status_code=400, detail="max_results must be between 1 and 1000"
        )


@search_router.post("/search", response_model=SearchResultResponse)
async def search_datasets(request: SearchRequest):
    """Search GEO datasets with natural language query."""
    try:
        # Validate input
        validate_search_input(request)

        from .main import active_queries, pipeline

        if not pipeline:
            raise HTTPException(
                status_code=503, detail="Pipeline not initialized"
            )

        # Generate unique query ID
        query_id = f"search_{uuid.uuid4().hex[:8]}"

        # Create initial result for internal tracking
        result = SearchResult(
            query_id=query_id,
            original_query=request.query,
            status=QueryStatus.RUNNING,
            entities=[],
            metadata=[],
            expanded_query=None,
            processing_time=None,
            ai_summaries=None,
            error_message=None,
        )

        # Store in active queries
        active_queries[query_id] = result

        try:
            # Execute search
            start_time = datetime.utcnow()
            pipeline_result = await pipeline.search_datasets(
                query=request.query,
                max_results=request.max_results,
                include_sra=request.include_sra,
                organism=request.organism,
                assay_type=request.assay_type,
                date_from=request.date_from,
                date_to=request.date_to,
            )
            end_time = datetime.utcnow()

            # Convert pipeline result to API format
            result.status = QueryStatus.COMPLETED
            result.processing_time = (end_time - start_time).total_seconds()
            result.expanded_query = pipeline_result.expanded_query

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
            await manager.broadcast(
                WebSocketMessage(
                    type="search_completed",
                    query_id=query_id,
                    data={"results": len(result.metadata)},
                ).json()
            )

        except Exception as e:
            result.status = QueryStatus.FAILED
            result.error_message = str(e)
            logger.error(f"Search failed for query {query_id}: {e}")

        finally:
            # Update active queries
            active_queries[query_id] = result

        # Return frontend-compatible response
        return SearchResultResponse(
            metadata=result.metadata,
            total_count=len(result.metadata),
            query_id=result.query_id,
            original_query=result.original_query,
            expanded_query=result.expanded_query,
            status=result.status,
            processing_time=result.processing_time,
            entities=result.entities,
            ai_summaries=result.ai_summaries,
            error_message=result.error_message,
        )

    except Exception as e:
        logger.error(f"Search endpoint error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Dataset endpoints
@dataset_router.get("/dataset/{dataset_id}", response_model=DatasetMetadata)
async def get_dataset_info(dataset_id: str, include_sra: bool = False):
    """Get detailed information about a specific dataset."""
    try:
        from .main import pipeline

        if not pipeline:
            raise HTTPException(
                status_code=503, detail="Pipeline not initialized"
            )

        # Execute dataset info request
        result = await pipeline.get_dataset_info(
            dataset_id=dataset_id, include_sra=include_sra
        )

        # Convert to API format
        return DatasetMetadata(
            id=result.get("id", dataset_id),
            title=result.get("title", ""),
            summary=result.get("summary", ""),
            organism=result.get("organism"),
            platform=result.get("platform"),
            sample_count=result.get("sample_count"),
            submission_date=result.get("submission_date"),
            last_update_date=result.get("last_update_date"),
            pubmed_id=result.get("pubmed_id"),
            sra_info=result.get("sra_info"),
        )

    except Exception as e:
        logger.error(f"Dataset info error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Analysis endpoints
@analysis_router.post("/analyze", response_model=SearchResult)
async def analyze_dataset(request: AnalyzeRequest):
    """Analyze a dataset with NLP processing."""
    try:
        from .main import active_queries, pipeline

        if not pipeline:
            raise HTTPException(
                status_code=503, detail="Pipeline not initialized"
            )

        query_id = f"analyze_{uuid.uuid4().hex[:8]}"

        # Create initial result
        result = SearchResult(
            query_id=query_id,
            original_query=f"analyze:{request.dataset_id}",
            status=QueryStatus.RUNNING,
            entities=[],
            metadata=[],
        )

        active_queries[query_id] = result

        try:
            # Execute analysis
            start_time = datetime.utcnow()
            analysis_result = await pipeline.analyze_dataset(
                dataset_id=request.dataset_id,
                include_entity_linking=request.include_entity_linking,
            )
            end_time = datetime.utcnow()

            # Update result
            result.status = QueryStatus.COMPLETED
            result.processing_time = (end_time - start_time).total_seconds()

            # Convert entities from analysis
            for entity in analysis_result.get("entities", []):
                result.entities.append(
                    EntityInfo(
                        text=entity.get("text", ""),
                        label=entity.get("label", ""),
                        confidence=entity.get("confidence"),
                        start=entity.get("start"),
                        end=entity.get("end"),
                    )
                )

            # Add dataset metadata if available
            if "metadata" in analysis_result:
                metadata = analysis_result["metadata"]
                result.metadata.append(
                    DatasetMetadata(
                        id=metadata.get("id", request.dataset_id),
                        title=metadata.get("title", ""),
                        summary=metadata.get("summary", ""),
                        organism=metadata.get("organism"),
                        platform=metadata.get("platform"),
                        sample_count=metadata.get("sample_count"),
                        submission_date=metadata.get("submission_date"),
                        last_update_date=metadata.get("last_update_date"),
                        pubmed_id=metadata.get("pubmed_id"),
                    )
                )

        except Exception as e:
            result.status = QueryStatus.FAILED
            result.error_message = str(e)
            logger.error(f"Analysis failed for {request.dataset_id}: {e}")

        finally:
            active_queries[query_id] = result

        return result

    except Exception as e:
        logger.error(f"Analysis endpoint error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Batch processing endpoints
@batch_router.post("/batch", response_model=BatchResult)
async def process_batch(request: BatchRequest):
    """Process multiple queries in batch."""
    try:
        from .main import active_queries, pipeline

        if not pipeline:
            raise HTTPException(
                status_code=503, detail="Pipeline not initialized"
            )

        batch_id = f"batch_{uuid.uuid4().hex[:8]}"

        # Create batch result
        batch_result = BatchResult(
            batch_id=batch_id,
            total_queries=len(request.queries),
            status=QueryStatus.RUNNING,
            results=[],
        )

        active_queries[batch_id] = batch_result

        try:
            # Process each query
            for i, query in enumerate(request.queries):
                try:
                    # Execute individual search
                    pipeline_result = await pipeline.search_datasets(
                        query=query, max_results=request.max_results
                    )

                    # Create search result
                    search_result = SearchResult(
                        query_id=f"{batch_id}_query_{i+1}",
                        original_query=query,
                        expanded_query=pipeline_result.expanded_query,
                        status=QueryStatus.COMPLETED,
                        entities=[],
                        metadata=[],
                    )

                    # Convert entities and metadata
                    for (
                        entity_type,
                        entity_list,
                    ) in pipeline_result.entities.items():
                        for entity in entity_list:
                            search_result.entities.append(
                                EntityInfo(
                                    text=entity.get("text", ""),
                                    label=entity_type,
                                    confidence=entity.get("confidence"),
                                    start=entity.get("start"),
                                    end=entity.get("end"),
                                )
                            )

                    for metadata in pipeline_result.metadata:
                        search_result.metadata.append(
                            DatasetMetadata(
                                id=metadata.get("id", ""),
                                title=metadata.get("title", ""),
                                summary=metadata.get("summary", ""),
                                organism=metadata.get("organism"),
                                platform=metadata.get("platform"),
                            )
                        )

                    batch_result.results.append(search_result)
                    batch_result.completed_queries += 1

                    # Broadcast progress
                    await manager.broadcast(
                        WebSocketMessage(
                            type="batch_progress",
                            query_id=batch_id,
                            data={
                                "completed": batch_result.completed_queries,
                                "total": batch_result.total_queries,
                            },
                        ).json()
                    )

                except Exception as e:
                    # Handle individual query failure
                    failed_result = SearchResult(
                        query_id=f"{batch_id}_query_{i+1}",
                        original_query=query,
                        status=QueryStatus.FAILED,
                        error_message=str(e),
                        entities=[],
                        metadata=[],
                    )
                    batch_result.results.append(failed_result)
                    batch_result.failed_queries += 1

            # Update batch status
            batch_result.status = QueryStatus.COMPLETED
            batch_result.completed_at = datetime.utcnow()

        except Exception as e:
            batch_result.status = QueryStatus.FAILED
            logger.error(f"Batch processing failed: {e}")

        finally:
            active_queries[batch_id] = batch_result

        return batch_result

    except Exception as e:
        logger.error(f"Batch endpoint error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Configuration endpoints
@config_router.get("/config", response_model=Dict[str, str])
async def get_all_config():
    """Get all configuration values."""
    try:
        from .main import config

        if not config:
            raise HTTPException(
                status_code=503, detail="Configuration not loaded"
            )

        return {
            "NCBI_EMAIL": config.ncbi.email,
            "NCBI_API_KEY": "***" if config.ncbi.api_key else "",
            "MAX_CONCURRENT_REQUESTS": str(config.ncbi.max_concurrent_requests),
            "REQUEST_DELAY": str(config.ncbi.request_delay),
        }

    except Exception as e:
        logger.error(f"Config get error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@config_router.get("/config/{key}", response_model=ConfigResponse)
async def get_config_value(key: str):
    """Get a specific configuration value."""
    try:
        from .main import config

        if not config:
            raise HTTPException(
                status_code=503, detail="Configuration not loaded"
            )

        # Map API keys to config values
        config_mapping = {
            "NCBI_EMAIL": config.ncbi.email,
            "NCBI_API_KEY": "***" if config.ncbi.api_key else "",
            "MAX_CONCURRENT_REQUESTS": str(config.ncbi.max_concurrent_requests),
            "REQUEST_DELAY": str(config.ncbi.request_delay),
        }

        if key not in config_mapping:
            raise HTTPException(
                status_code=404, detail=f"Configuration key '{key}' not found"
            )

        return ConfigResponse(
            key=key,
            value=config_mapping[key],
            description=f"Configuration value for {key}",
        )

    except Exception as e:
        logger.error(f"Config get error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Status endpoints
@status_router.get("/status", response_model=StatusResponse)
async def get_system_status():
    """Get system status information."""
    try:
        from .main import active_queries, config, pipeline

        return StatusResponse(
            status="healthy",
            configuration_loaded=config is not None,
            ncbi_email=config.ncbi.email if config else None,
            pipeline_initialized=pipeline is not None,
            active_queries=len(active_queries),
        )

    except Exception as e:
        logger.error(f"Status endpoint error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@status_router.get("/status/{query_id}", response_model=SearchResult)
async def get_query_status(query_id: str):
    """Get status of a specific query."""
    try:
        from .main import active_queries

        if query_id not in active_queries:
            raise HTTPException(
                status_code=404, detail=f"Query '{query_id}' not found"
            )

        return active_queries[query_id]

    except Exception as e:
        logger.error(f"Query status error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# WebSocket endpoints
@websocket_router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates."""
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and handle incoming messages
            data = await websocket.receive_text()

            # Parse message
            try:
                message = json.loads(data)
                if message.get("type") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except json.JSONDecodeError:
                await websocket.send_text(
                    json.dumps({"type": "error", "message": "Invalid JSON"})
                )

    except WebSocketDisconnect:
        manager.disconnect(websocket)
