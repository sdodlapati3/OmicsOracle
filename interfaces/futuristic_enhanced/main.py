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
    import requests
    import httpx
    BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
    logger.info(f"Enhanced interface will connect to backend at: {BACKEND_URL}")
except ImportError as e:
    logger.warning(f"Failed to import backend integration modules: {e}")
    BACKEND_URL = None


# Enhanced API models for Clean Architecture integration
class EnhancedSearchRequest(BaseModel):
    query: str = Field(..., description="Search query for biomedical datasets")
    filters: Dict[str, Any] = Field(default_factory=dict, description="Search filters")
    max_results: int = Field(10, description="Maximum number of results")
    include_metadata: bool = Field(True, description="Include metadata in response")
    enable_ai_summary: bool = Field(True, description="Enable AI-powered summary")


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
                "/api/v2/search/enhanced",
                json=request.dict(),
                timeout=30.0
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            logger.error(f"Backend search failed: {e}")
            raise HTTPException(status_code=503, detail="Backend service unavailable")
    
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
        logger.info(f"Set NCBI_EMAIL environment variable to {os.environ['NCBI_EMAIL']}")

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

        # Initialize pipeline with caching explicitly disabled
        logger.info("Creating OmicsOracle pipeline instance with disable_cache=True")
        pipeline = OmicsOracle(config, disable_cache=True)
        
        if pipeline is None:
            logger.error("Pipeline initialization returned None")
            raise Exception("Pipeline initialization failed")

        # Set up progress callback for real-time updates
        logger.info("Setting up progress callback")
        pipeline.set_progress_callback(send_progress_to_frontend)

        logger.info("[OK] OmicsOracle pipeline initialized successfully with caching disabled")
    except Exception as e:
        logger.error(f"[ERROR] Failed to initialize pipeline: {e}")
        # Print the full exception traceback for debugging
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        pipeline = None


@app.get("/", response_class=HTMLResponse)
async def futuristic_interface():
    """Serve the futuristic interface"""
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>OmicsOracle - Futuristic Research Platform</title>
        <link rel="stylesheet" href="/static/css/main_clean.css">
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="min-h-screen">
        <div id="app" class="container mx-auto px-4 py-8">
            <!-- Header -->
            <header class="text-center mb-12">
                <h1 class="text-6xl font-bold text-white mb-4">
                    🧬 OmicsOracle
                </h1>
                <p class="text-xl text-gray-200 mb-6">
                    Next-Generation Biomedical Research Intelligence Platform
                </p>
            </header>

            <!-- Main Interface -->
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
                <!-- Left Panel: Search -->
                <div class="lg:col-span-2">
                    <!-- Smart Search -->
                    <div class="glass-effect rounded-xl p-6 mb-8">
                        <h2 class="text-2xl font-bold text-white mb-4">🔍 Intelligent Search</h2>
                        <div class="search-container">
                            <input
                                id="search-input"
                                type="text"
                                placeholder="Search for biomedical datasets (e.g., 'cancer RNA-seq', 'diabetes microarray')..."
                                class="w-full p-4 rounded-lg bg-gray-800 text-white border border-gray-600 focus:border-blue-500 focus:outline-none"
                            >
                            <button id="search-btn" class="w-full mt-4 bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 px-6 rounded-lg transition-colors">
                                🚀 Search NCBI GEO Database
                            </button>
                            <div class="flex justify-between items-center mt-4">
                                <div class="flex items-center">
                                    <label for="max-results" class="mr-2 text-gray-300">Max Results:</label>
                                    <select id="max-results" class="bg-gray-800 text-white border border-gray-600 rounded p-2">
                                        <option value="10">10</option>
                                        <option value="20">20</option>
                                        <option value="50">50</option>
                                        <option value="100">100</option>
                                    </select>
                                </div>
                                <div class="text-gray-400 text-xs">Higher values may increase search time</div>
                            </div>
                            <div class="mt-3 p-3 bg-blue-900 bg-opacity-30 rounded-lg border border-blue-600">
                                <div class="text-blue-300 text-sm">
                                    ⏱️ <strong>Search Times:</strong> Complex biomedical searches may take 1-3 minutes with real-time progress updates
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Live Query Progress Monitor -->
                    <div id="live-monitor-container" class="glass-effect rounded-xl p-6 mb-8" style="display: none;">
                        <h3 class="text-xl font-bold text-white mb-4">🔄 Live Query Progress</h3>
                        <div class="relative mb-4">
                            <div id="progress-bar-container" class="w-full bg-gray-700 rounded-full h-4 overflow-hidden">
                                <div id="progress-bar" class="bg-blue-600 h-4 rounded-full transition-all duration-300" style="width: 0%"></div>
                            </div>
                            <div id="progress-percentage" class="absolute right-0 top-0 -mt-6 text-gray-300 text-sm">0%</div>
                        </div>
                        <div id="live-monitor" class="bg-black bg-opacity-80 rounded-lg p-4 h-64 overflow-y-auto font-mono text-sm">
                            <div class="text-green-400">🚀 Query monitor ready...</div>
                        </div>
                        <div class="mt-2 flex justify-between items-center">
                            <div class="text-gray-400 text-xs">Real-time backend monitoring</div>
                            <div class="flex items-center">
                                <span id="current-stage" class="text-blue-400 text-xs mr-3"></span>
                                <button id="clear-monitor-btn" class="text-gray-400 hover:text-white text-xs">Clear</button>
                            </div>
                        </div>
                    </div>

                    <!-- Search Results -->
                    <div class="glass-effect rounded-xl p-6">
                        <h3 class="text-xl font-bold text-white mb-4">📊 Search Results</h3>
                        <div id="search-results">
                            <div class="text-center py-8 text-gray-300">
                                Enter a search query to find biomedical datasets...
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Right Panel: Status & Updates -->
                <div class="lg:col-span-1">
                    <!-- Live Updates -->
                    <div class="glass-effect rounded-xl p-6 mb-8">
                        <h2 class="text-2xl font-bold text-white mb-4">📡 Live Updates</h2>
                        <div id="live-updates" class="space-y-2">
                            <div class="text-gray-300 text-center py-4">
                                🔮 Ready for biomedical search
                            </div>
                        </div>
                    </div>

                    <!-- System Monitor -->
                    <div class="glass-effect rounded-xl p-6">
                        <h2 class="text-2xl font-bold text-white mb-4">⚡ System Status</h2>
                        <div id="system-stats" class="space-y-2">
                            <div class="flex justify-between text-white">
                                <span>Search Queries:</span>
                                <span id="search-queries">0</span>
                            </div>
                            <div class="flex justify-between text-white">
                                <span>Response Time:</span>
                                <span id="avg-response-time">--</span>
                            </div>
                            <div class="flex justify-between text-white">
                                <span>Pipeline Status:</span>
                                <span id="pipeline-status">Active</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <script src="/static/js/main_clean.js"></script>
    </body>
    </html>
    """


@app.post("/api/search")
async def search_datasets(
    request: SearchRequest, background_tasks: BackgroundTasks
):
    """Search for biomedical datasets using the OmicsOracle pipeline"""
    await log_to_frontend(
        f"[SEARCH] New search query received: '{request.query}'", "info"
    )

    if not pipeline:
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
        if not pipeline:
            raise Exception("Pipeline not initialized")

        logger.info(f"[SEARCH] Starting pipeline query processing for: {query}")
        await log_to_frontend(
            "[SEARCH] Starting pipeline query processing...", "info"
        )

        await log_to_frontend(
            "[DATA] Connecting to NCBI GEO database...", "info"
        )

        # Use the pipeline's process_query method (it's async!)
        # This will handle GEO query preparation, extraction, and AI summary
        query_result = await pipeline.process_query(
            query, max_results=max_results
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
                    "summary": metadata.get("summary"),  # Can be None (GEO summary)
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
                    "geo_summary": metadata.get("summary"),  # Original GEO summary
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
    status = "healthy" if pipeline is not None else "unavailable"
    
    pipeline_info = {}
    if pipeline is not None:
        # Get pipeline details when available
        pipeline_info = {
            "geo_client_available": hasattr(pipeline, "geo_client") and pipeline.geo_client is not None,
            "cache_disabled": getattr(pipeline, "disable_cache", False),
            "summarizer_available": hasattr(pipeline, "summarizer") and pipeline.summarizer is not None,
        }
        
        # Check NCBI email configuration
        if hasattr(pipeline, "config") and hasattr(pipeline.config, "ncbi"):
            pipeline_info["ncbi_email"] = getattr(pipeline.config.ncbi, "email", "Not set")
        
        # Check if critical components are ready
        pipeline_info["critical_components_ready"] = all([
            pipeline_info.get("geo_client_available", False),
            pipeline_info.get("summarizer_available", False)
        ])
    
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
        "message": "Futuristic interface ready" if status == "healthy" else "Pipeline not initialized"
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
