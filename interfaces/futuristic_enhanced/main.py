"""
Futuristic Interface for OmicsOracle - Next Generation Research Platform

This module implements a cutting-edge interface that integrates with the existing
OmicsOracle pipeline for proper data search and AI summarization.
"""

import logging
import os
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import (
    BackgroundTasks,
    FastAPI,
    HTTPException,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# Configure logging first
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Add the main project root to path to import existing modules
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# Apply NCBI email patch to ensure Bio.Entrez email is properly set
try:
    # Load environment variables first
    os.environ["NCBI_EMAIL"] = "omicsoracle@example.com"

    # Try to import the patch if it exists
    if Path(project_root / "entrez_patch.py").exists():
        sys.path.insert(0, str(project_root))
        import entrez_patch

        logger.info("Successfully applied Bio.Entrez email patch")
    else:
        logger.warning(
            "entrez_patch.py not found - NCBI email may not be correctly configured"
        )
except Exception as e:
    logger.warning(f"Failed to apply Bio.Entrez email patch: {e}")

# Import existing OmicsOracle modules
try:
    # Try to import from Clean Architecture backend
    import httpx
    import requests

    BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
    logger.info(f"Enhanced interface will connect to backend at: {BACKEND_URL}")
except ImportError as e:
    logger.warning(f"Failed to import backend integration modules: {e}")
    BACKEND_URL = None

# Import OmicsOracle classes
try:
    from src.omics_oracle.core.config import Config
    from src.omics_oracle.pipeline.pipeline import OmicsOracle

    logger.info("Successfully imported OmicsOracle classes")
except ImportError as e:
    logger.error(f"Failed to import OmicsOracle classes: {e}")

    # Define fallback classes to prevent crash
    class OmicsOracle:
        def __init__(self, *args, **kwargs):
            raise NotImplementedError("OmicsOracle class not available")

    class Config:
        def __init__(self):
            self.ncbi = type(
                "NCBIConfig", (), {"email": "omicsoracle@example.com"}
            )()


# Enhanced API models for Clean Architecture integration
class SearchRequest(BaseModel):
    query: str = Field(..., description="Search query for biomedical datasets")
    max_results: int = Field(
        10,
        description="Maximum number of results (5, 10, 20, 50, 100, or 1000 for 'All Results')",
    )
    search_type: str = Field(
        "comprehensive",
        description="Search type (quick, comprehensive, or advanced)",
    )
    disable_cache: bool = Field(
        False, description="Force fresh data by disabling the cache"
    )
    timestamp: Optional[float] = Field(
        None, description="Client timestamp for cache-busting"
    )


class SearchResponse(BaseModel):
    query: str
    results: List[Dict[str, Any]]
    total_found: int
    search_time: float
    timestamp: float


class EnhancedSearchRequest(BaseModel):
    query: str = Field(..., description="Search query for biomedical datasets")
    filters: Dict[str, Any] = Field(
        default_factory=dict, description="Search filters"
    )
    max_results: int = Field(
        10,
        description="Maximum number of results (5, 10, 20, 50, 100, or 1000 for 'All Results')",
    )
    include_metadata: bool = Field(
        True, description="Include metadata in response"
    )
    enable_ai_summary: bool = Field(
        True, description="Enable AI-powered summary"
    )


class EnhancedSearchResponse(BaseModel):
    query: str
    datasets: List[Dict[str, Any]]
    metadata: Optional[Dict[str, Any]] = None
    ai_summary: Optional[str] = None
    total_found: int
    search_time: float
    api_version: str = "v2_enhanced"
    timestamp: float


# FastAPI app configuration for Enhanced Interface
app = FastAPI(
    title="OmicsOracle Enhanced Futuristic Interface",
    description="Next-generation biomedical research platform with Clean Architecture integration",
    version="2.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files
static_path = Path(__file__).parent / "static"
static_path.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_path)), name="static")


# Backend client for Clean Architecture integration
class BackendClient:
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.session = None

    async def __aenter__(self):
        self.session = httpx.AsyncClient(base_url=self.base_url)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.aclose()

    async def search_enhanced(self, request: EnhancedSearchRequest) -> dict:
        """Perform enhanced search via Clean Architecture backend"""
        try:
            response = await self.session.post(
                "/api/v2/search/enhanced", json=request.dict(), timeout=30.0
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Backend search failed: {e}")
            raise HTTPException(
                status_code=503, detail="Backend service unavailable"
            )

    async def get_dataset_details(self, dataset_id: str) -> dict:
        """Get dataset details from backend"""
        try:
            response = await self.session.get(f"/api/v2/datasets/{dataset_id}")
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Failed to get dataset details: {e}")
            raise HTTPException(status_code=404, detail="Dataset not found")

    async def health_check(self) -> dict:
        """Check backend health"""
        try:
            response = await self.session.get("/api/v2/health")
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError:
            return {"status": "unavailable", "backend": "disconnected"}


# WebSocket connection manager for live monitoring
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(
            f"WebSocket connected. Total connections: {len(self.active_connections)}"
        )

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(
            f"WebSocket disconnected. Total connections: {len(self.active_connections)}"
        )

    async def broadcast(self, message: str):
        """Broadcast message to all connected clients"""
        if self.active_connections:
            disconnected = []
            for connection in self.active_connections:
                try:
                    await connection.send_text(message)
                except Exception as e:
                    logger.warning(f"Failed to send to WebSocket: {e}")
                    disconnected.append(connection)

            # Remove disconnected clients
            for conn in disconnected:
                self.disconnect(conn)

    async def broadcast_progress(
        self,
        query_id: str,
        stage: str,
        message: str,
        percentage: float,
        detail: Optional[Dict[str, Any]] = None,
    ):
        """Broadcast progress update to all connected clients"""
        progress_data = {
            "type": "progress",
            "query_id": query_id,
            "stage": stage,
            "message": message,
            "percentage": percentage,
            "detail": detail or {},
            "timestamp": time.time(),
        }

        # Format message as HTML for UI display
        timestamp = time.strftime("%H:%M:%S", time.localtime())

        # Determine color based on stage
        color_class = "text-blue-400"
        if "error" in stage or "failed" in stage:
            color_class = "text-red-400"
        elif "complete" in stage or "success" in stage:
            color_class = "text-green-400"
        elif "warning" in stage or "skip" in stage:
            color_class = "text-yellow-400"

        # Format progress percentage
        progress_text = f"{percentage:.0f}%"

        # Create HTML message
        html_message = f'<div class="{color_class}"><span class="font-mono">[{timestamp}]</span> <span class="font-mono inline-block w-10 text-right">{progress_text}</span> {message}</div>'

        # Broadcast both the JSON data and HTML format
        if self.active_connections:
            disconnected = []
            for connection in self.active_connections:
                try:
                    # Send formatted HTML for display
                    await connection.send_text(html_message)

                    # Send structured JSON data for advanced clients
                    await connection.send_json(progress_data)
                except Exception as e:
                    logger.warning(f"Failed to send progress to WebSocket: {e}")
                    disconnected.append(connection)

            # Remove disconnected clients
            for conn in disconnected:
                self.disconnect(conn)


# Global connection manager
manager = ConnectionManager()


async def log_to_frontend(message: str, level: str = "info"):
    """Send log message to frontend via WebSocket"""
    timestamp = time.strftime("%H:%M:%S", time.localtime())
    color_map = {
        "info": "text-white",
        "success": "text-green-400",
        "warning": "text-yellow-400",
        "error": "text-red-400",
        "debug": "text-blue-400",
    }
    color = color_map.get(level, "text-white")

    formatted_message = f'<div class="{color}">[{timestamp}] {message}</div>'
    await manager.broadcast(formatted_message)


async def send_progress_to_frontend(query_id: str, event):
    """Send progress event to frontend via WebSocket"""
    # Log each progress event for debugging
    logger.info(
        f"[PROGRESS] {event.stage} - {event.message} ({event.percentage:.1f}%)"
    )

    # Log detailed event information at debug level
    if event.detail:
        logger.debug(f"[PROGRESS_DETAIL] {event.stage}: {event.detail}")

    # Track progress events in a file for analysis
    with open("progress_events_raw.log", "a") as f:
        f.write(
            f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {query_id} | {event.stage} | {event.message} | {event.percentage:.1f}%\n"
        )

    # Send to frontend via WebSocket
    await manager.broadcast_progress(
        query_id=query_id,
        stage=event.stage,
        message=event.message,
        percentage=event.percentage,
        detail=event.detail,
    )


# Global pipeline instance
pipeline: Optional[OmicsOracle] = None


@app.on_event("startup")
async def startup_event():
    """Initialize the OmicsOracle pipeline on startup"""
    global pipeline
    try:
        logger.info("=> Initializing OmicsOracle Pipeline...")

        # Set NCBI email in environment variable
        os.environ["NCBI_EMAIL"] = "omicsoracle@example.com"
        logger.info(
            f"Set NCBI_EMAIL environment variable to {os.environ['NCBI_EMAIL']}"
        )

        # Create configuration
        config = Config()

        # Ensure NCBI email is configured in the config object
        if hasattr(config, "ncbi"):
            if not hasattr(config.ncbi, "email") or not config.ncbi.email:
                logger.info("Setting NCBI email in config object")
                setattr(config.ncbi, "email", "omicsoracle@example.com")
            logger.info(f"NCBI email in config: {config.ncbi.email}")
        else:
            logger.warning("Config object does not have ncbi attribute")

        # Ensure Bio.Entrez.email is set directly as well
        try:
            from Bio import Entrez

            Entrez.email = "omicsoracle@example.com"
            logger.info(f"Direct Bio.Entrez.email set to: {Entrez.email}")
        except ImportError:
            logger.warning("Bio.Entrez not available")

        # Initialize pipeline
        logger.info("Creating OmicsOracle pipeline instance")
        pipeline = OmicsOracle(config)

        if pipeline is None:
            logger.error("Pipeline initialization returned None")
            raise Exception("Pipeline initialization failed")

        # Set up progress callback for real-time updates (if available)
        logger.info("Setting up progress callback")
        try:
            if hasattr(pipeline, "set_progress_callback"):
                pipeline.set_progress_callback(send_progress_to_frontend)
                logger.info("Progress callback successfully configured")
            else:
                logger.warning("Pipeline does not support progress callbacks")
        except Exception as callback_error:
            logger.warning(f"Failed to set progress callback: {callback_error}")

        logger.info("[OK] OmicsOracle pipeline initialized successfully")

        # Store pipeline in app state for use by API endpoints
        app.state.pipeline = pipeline

    except Exception as e:
        logger.error(f"[ERROR] Failed to initialize pipeline: {e}")
        # Print the full exception traceback for debugging
        import traceback

        logger.error(f"Traceback: {traceback.format_exc()}")
        pipeline = None
        app.state.pipeline = None


@app.get("/", response_class=HTMLResponse)
async def futuristic_interface():
    """Serve the futuristic interface from static HTML file"""
    static_path = Path(__file__).parent / "static" / "index.html"
    with open(static_path, "r", encoding="utf-8") as f:
        return f.read()


@app.post("/api/search")
async def search_datasets(
    request: SearchRequest, background_tasks: BackgroundTasks
):
    """Search for biomedical datasets using the OmicsOracle pipeline"""
    await log_to_frontend(
        f"[SEARCH] New search query received: '{request.query}'", "info"
    )

    if not hasattr(app.state, "pipeline") or not app.state.pipeline:
        await log_to_frontend("[ERROR] Pipeline not available", "error")
        raise HTTPException(
            status_code=503, detail="OmicsOracle pipeline not available"
        )

    search_start_time = time.time()
    await log_to_frontend(
        f"[START] Starting search with max_results={request.max_results}",
        "info",
    )

    try:
        logger.info(f"[SEARCH] Processing search query: {request.query}")
        await log_to_frontend(
            "[AI] Initializing AI-powered search pipeline...", "info"
        )

        # Use the existing OmicsOracle pipeline to process the query
        result = await process_search_query(request.query, request.max_results)

        search_time = time.time() - search_start_time
        await log_to_frontend(
            f"[OK] Search completed in {search_time:.2f}s", "success"
        )
        await log_to_frontend(
            f"[RESULTS] Found {len(result['datasets'])} relevant datasets",
            "success",
        )

        return SearchResponse(
            query=request.query,
            results=result["datasets"],
            total_found=len(result["datasets"]),
            search_time=search_time,
            timestamp=time.time(),
        )

    except Exception as e:
        await log_to_frontend(f"[ERROR] Search failed: {str(e)}", "error")
        logger.error(f"[ERROR] Search failed: {e}")
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")


async def process_search_query(
    query: str, max_results: int = 10
) -> Dict[str, Any]:
    """Process search query using the existing OmicsOracle pipeline"""
    try:
        # Check if pipeline is available
        if not hasattr(app.state, "pipeline") or not app.state.pipeline:
            raise Exception("Pipeline not initialized")

        # Validate max_results
        valid_values = [5, 10, 20, 50, 100, 1000]
        if max_results not in valid_values:
            logger.warning(
                f"Invalid max_results value: {max_results}. Defaulting to 10."
            )
            max_results = 10

        # Handle "All Results" option (value of 1000)
        actual_max_results = 1000 if max_results == 1000 else max_results

        logger.info(
            f"[SEARCH] Starting pipeline query processing for: {query} with max_results={max_results}"
        )
        await log_to_frontend(
            "[SEARCH] Starting pipeline query processing...", "info"
        )

        await log_to_frontend(
            "[DATA] Connecting to NCBI GEO database...", "info"
        )

        # First try to import the enhanced query handler for better handling of complex queries
        try:
            from src.omics_oracle.search.enhanced_query_handler import (
                perform_multi_strategy_search,
            )

            await log_to_frontend(
                "[SEARCH] Using enhanced query handling for complex queries...",
                "info",
            )

            # Use the enhanced query handler first
            geo_ids, metadata_info = await perform_multi_strategy_search(
                app.state.pipeline, query, max_results=actual_max_results
            )

            # Create a compatible result object
            if geo_ids:
                # Get components used in the search from metadata_info
                components = metadata_info.get("components", {})
                search_strategy = metadata_info.get(
                    "search_strategy", "original"
                )
                query_used = metadata_info.get("query_used", query)

                # Add search strategy information to the frontend
                if search_strategy == "alternative":
                    await log_to_frontend(
                        f"[SEARCH] Used alternative query: '{query_used}' for better results",
                        "info",
                    )

                    # If we have identified components, show them to the user
                    components_found = [
                        k
                        for k, v in components.items()
                        if v and k != "original_query"
                    ]
                    if components_found:
                        await log_to_frontend(
                            f"[ANALYSIS] Identified query components: {', '.join(components_found)}",
                            "info",
                        )

                # Create a compatible result object with all the necessary fields
                query_result = type(
                    "QueryResult",
                    (),
                    {
                        "geo_ids": geo_ids,
                        "metadata": metadata_info.get("metadata", []),
                        "ai_summaries": metadata_info.get("ai_summaries", {}),
                        "intent": f"Find {components.get('data_type', 'gene expression data')} related to {components.get('disease', components.get('tissue', 'biomedical conditions'))} in {components.get('organism', 'organisms')}",
                        "duration": 0.0,
                        "status": type("Status", (), {"value": "COMPLETED"}),
                    },
                )
            else:
                # Fall back to standard query processing if no results from enhanced search
                await log_to_frontend(
                    "[SEARCH] Enhanced search found no results, trying standard pipeline...",
                    "info",
                )
                # Use the pipeline's process_query method (it's async!)
                query_result = await app.state.pipeline.process_query(
                    query, max_results=actual_max_results
                )

        except ImportError:
            # If enhanced query handler is not available, use the standard pipeline
            await log_to_frontend(
                "[SEARCH] Using standard pipeline search...", "info"
            )
            # Use the pipeline's process_query method (it's async!)
            query_result = await app.state.pipeline.process_query(
                query, max_results=actual_max_results
            )

        await log_to_frontend(
            f"[RESULTS] Pipeline results: {len(query_result.geo_ids)} GEO IDs found",
            "success",
        )
        await log_to_frontend(
            f"[DEBUG] DEBUG: Metadata entries: {len(query_result.metadata)}",
            "debug",
        )
        await log_to_frontend(
            f"[DEBUG] DEBUG: AI summaries keys: {list(query_result.ai_summaries.keys()) if query_result.ai_summaries else 'None'}",
            "debug",
        )
        logger.info(
            f"[RESULTS] Pipeline results: {len(query_result.geo_ids)} GEO IDs found, {len(query_result.metadata)} metadata entries"
        )

        # Extract and format the results
        datasets = []

        await log_to_frontend(
            "[AI] Processing metadata and generating AI insights...", "info"
        )

        # Check if we have GEO IDs (even without metadata)
        if query_result.geo_ids:
            for i, geo_id in enumerate(query_result.geo_ids[:max_results]):
                await log_to_frontend(
                    f"[PROGRESS] Processing dataset {i + 1}/{min(len(query_result.geo_ids), max_results)}: {geo_id}",
                    "debug",
                )
                # Get metadata if available, otherwise use defaults
                metadata = {}
                if i < len(query_result.metadata):
                    metadata = query_result.metadata[i] or {}

                await log_to_frontend(
                    f"[DEBUG] DEBUG: {geo_id} metadata keys: {list(metadata.keys()) if metadata else 'Empty'}",
                    "debug",
                )

                # Clean up organism field - use only real data
                organism = metadata.get("organism", "").strip()
                if not organism:
                    organism = None  # Don't show organism if not available

                # Get platform info (skip if Unknown platform)
                platform = metadata.get("platform", "").strip()
                if not platform or platform == "Unknown platform":
                    platform = None  # Don't display platform if unknown

                # Normalize relevance score - only use real scores
                raw_score = metadata.get("relevance_score", None)
                if raw_score is not None:
                    if raw_score > 1.0:
                        # Assume it's out of 5 or similar scale
                        relevance_score = min(raw_score / 5.0, 1.0)
                    else:
                        relevance_score = raw_score
                else:
                    # No relevance score available
                    relevance_score = None

                # Format publication date properly
                pub_date = "Date not available"
                if (
                    metadata.get("submission_date")
                    and metadata["submission_date"][0]
                ):
                    raw_date = metadata["submission_date"][0]
                    # If it's just a single character, it's probably incomplete
                    if len(raw_date) > 1:
                        pub_date = raw_date
                elif (
                    metadata.get("last_update_date")
                    and metadata["last_update_date"][0]
                ):
                    raw_date = metadata["last_update_date"][0]
                    if len(raw_date) > 1:
                        pub_date = raw_date
                elif metadata.get("pubdate"):
                    pub_date = metadata["pubdate"]
                # Get AI insights - only use real AI summaries, no fallbacks
                ai_insights = None
                if (
                    query_result.ai_summaries
                    and "individual_summaries" in query_result.ai_summaries
                ):
                    for summary_item in query_result.ai_summaries[
                        "individual_summaries"
                    ]:
                        if summary_item.get("accession") == geo_id:
                            ai_insights = summary_item.get("summary")
                            break

                dataset_info = {
                    "geo_id": geo_id,
                    "title": metadata.get("title"),  # Can be None
                    "summary": metadata.get(
                        "summary"
                    ),  # Can be None (GEO summary)
                    "organism": organism,  # Can be None
                    "sample_count": metadata.get("sample_count"),  # Can be None
                    "platform": platform,  # Can be None
                    "publication_date": pub_date
                    if pub_date != "Date not available"
                    else None,
                    "study_type": metadata.get("type"),  # Can be None
                    "ai_insights": ai_insights,  # Can be None (AI summary)
                    "relevance_score": relevance_score,  # Can be None
                    # Include both summaries explicitly for clarity
                    "geo_summary": metadata.get(
                        "summary"
                    ),  # Original GEO summary
                    "ai_summary": ai_insights,  # AI-generated summary
                }
                datasets.append(dataset_info)

            logger.info(f"[OK] Successfully formatted {len(datasets)} datasets")
            await log_to_frontend(
                f"[OK] Successfully processed {len(datasets)} datasets",
                "success",
            )

            # Sort datasets by actual data quality - only consider real metadata
            # Put datasets with complete real data first
            datasets.sort(
                key=lambda d: (
                    d.get("title") is not None,  # Has real title
                    d.get("summary") is not None,  # Has real summary
                    d.get("relevance_score", 0)
                    or 0,  # Real relevance score (handle None)
                ),
                reverse=True,
            )

        # Return empty results if nothing found - no fallback to mock data
        if not datasets:
            logger.warning("[WARNING] No datasets found from pipeline")
            return {
                "datasets": [],
                "query": query,
                "ai_insights": f"No results found for '{query}'. Please try a different search term.",
            }

        # Create AI insights message based only on real data
        datasets_with_metadata = [
            d for d in datasets if d.get("title") is not None
        ]
        datasets_with_summaries = [
            d for d in datasets if d.get("summary") is not None
        ]

        ai_insights = f"Found {len(datasets)} biomedical datasets for '{query}'"

        # Add real metadata quality summary
        if datasets_with_metadata:
            ai_insights += f" ({len(datasets_with_metadata)} with metadata)"
        if datasets_with_summaries:
            ai_insights += f" including {len(datasets_with_summaries)} with detailed summaries"
        ai_insights += "."

        if query_result.intent:
            ai_insights += f" Detected research intent: {query_result.intent}."
        if query_result.duration:
            ai_insights += f" Search completed in {query_result.duration:.2f}s."

        # Only show note about limited metadata if there are datasets without metadata
        datasets_without_metadata = len(datasets) - len(datasets_with_metadata)
        if datasets_without_metadata > 0:
            ai_insights += f" Note: {datasets_without_metadata} datasets have limited metadata from NCBI."

        await log_to_frontend(
            "[COMPLETE] Query processing complete!", "success"
        )

        return {
            "datasets": datasets,
            "query": query,
            "ai_insights": ai_insights,
        }

    except Exception as e:
        # Error in real pipeline - return actual error, no mock fallback
        logger.error(f"[ERROR] Error processing search query: {e}")
        raise Exception(f"Pipeline processing failed: {e}")


@app.get("/api/health")
async def health_check():
    """Health check endpoint with detailed pipeline status"""
    pipeline = getattr(app.state, "pipeline", None)
    status = "healthy" if pipeline is not None else "unavailable"

    pipeline_info = {}
    if pipeline is not None:
        # Get pipeline details when available
        pipeline_info = {
            "geo_client_available": hasattr(pipeline, "geo_client")
            and pipeline.geo_client is not None,
            "cache_disabled": getattr(pipeline, "disable_cache", False),
            "summarizer_available": hasattr(pipeline, "summarizer")
            and pipeline.summarizer is not None,
        }

        # Check NCBI email configuration
        if hasattr(pipeline, "config") and hasattr(pipeline.config, "ncbi"):
            pipeline_info["ncbi_email"] = getattr(
                pipeline.config.ncbi, "email", "Not set"
            )

        # Check if critical components are ready
        pipeline_info["critical_components_ready"] = all(
            [
                pipeline_info.get("geo_client_available", False),
                pipeline_info.get("summarizer_available", False),
            ]
        )

    # Include environment information
    env_info = {
        "NCBI_EMAIL": os.environ.get("NCBI_EMAIL", "Not set"),
        "python_version": sys.version,
    }

    # Try to check Bio.Entrez email
    try:
        from Bio import Entrez

        env_info["entrez_email"] = getattr(Entrez, "email", "Not set")
    except ImportError:
        env_info["entrez_email"] = "Bio.Entrez not available"

    return {
        "status": status,
        "timestamp": time.time(),
        "pipeline_available": pipeline is not None,
        "pipeline_info": pipeline_info,
        "environment": env_info,
        "message": "Futuristic interface ready"
        if status == "healthy"
        else "Pipeline not initialized",
    }


@app.websocket("/ws/monitor")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for live query monitoring"""
    await manager.connect(websocket)
    try:
        await log_to_frontend("[LIVE] Live monitoring connected", "success")
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)


# Store WebSocket messages for debugging
if Path("websocket_monitor.py").exists():
    try:
        sys.path.insert(0, str(project_root))
        from websocket_monitor import setup_websocket_monitoring

        app.state.connection_manager = manager
        setup_websocket_monitoring(app)
        logger.info("[OK] WebSocket monitoring enabled for debugging")
    except ImportError as e:
        logger.warning(f"[WARNING] WebSocket monitoring module not loaded: {e}")


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8001,
        reload=True,
        log_level="info",
    )
