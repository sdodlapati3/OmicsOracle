"""
Futuristic Interface for OmicsOracle - Next Generation Research Platform

This module implements a cutting-edge interface that integrates with the existing
OmicsOracle pipeline for proper data search and AI summarization.
"""

import asyncio
import logging
import sys
import time
import uuid
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
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# Add the main project root to path to import existing modules
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# Import existing OmicsOracle modules
from src.omics_oracle.core.config import Config
from src.omics_oracle.pipeline.pipeline import (
    OmicsOracle,
    QueryResult,
    ResultFormat,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Pydantic models for API
class SearchRequest(BaseModel):
    query: str = Field(..., description="Search query for biomedical datasets")
    max_results: int = Field(
        10, description="Maximum number of results to return"
    )
    search_type: str = Field(
        "comprehensive", description="Type of search to perform"
    )


class SearchResponse(BaseModel):
    query: str
    results: List[Dict[str, Any]]
    total_found: int
    search_time: float
    timestamp: float


# FastAPI app configuration
app = FastAPI(
    title="OmicsOracle Futuristic Interface",
    description="Next-generation biomedical research platform",
    version="2.0.0",
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files
static_path = Path(__file__).parent / "static"
static_path.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_path)), name="static")


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


# Global pipeline instance
pipeline: Optional[OmicsOracle] = None


@app.on_event("startup")
async def startup_event():
    """Initialize the OmicsOracle pipeline on startup"""
    global pipeline
    try:
        logger.info("🚀 Initializing OmicsOracle Pipeline...")
        config = Config()
        pipeline = OmicsOracle(config)
        logger.info("✅ OmicsOracle pipeline initialized successfully")
    except Exception as e:
        logger.error(f"❌ Failed to initialize pipeline: {e}")
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
                        </div>
                    </div>

                    <!-- Live Query Progress Monitor -->
                    <div id="live-monitor-container" class="glass-effect rounded-xl p-6 mb-8" style="display: none;">
                        <h3 class="text-xl font-bold text-white mb-4">🔄 Live Query Progress</h3>
                        <div id="live-monitor" class="bg-black bg-opacity-80 rounded-lg p-4 h-64 overflow-y-auto font-mono text-sm">
                            <div class="text-green-400">🚀 Query monitor ready...</div>
                        </div>
                        <div class="mt-2 flex justify-between items-center">
                            <div class="text-gray-400 text-xs">Real-time backend monitoring</div>
                            <button id="clear-monitor-btn" class="text-gray-400 hover:text-white text-xs">Clear</button>
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
                                System ready for search...
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
        f"🔍 New search query received: '{request.query}'", "info"
    )

    if not pipeline:
        await log_to_frontend("❌ Pipeline not available", "error")
        raise HTTPException(
            status_code=503, detail="OmicsOracle pipeline not available"
        )

    search_start_time = time.time()
    await log_to_frontend(
        f"⚡ Starting search with max_results={request.max_results}", "info"
    )

    try:
        logger.info(f"🔍 Processing search query: {request.query}")
        await log_to_frontend(
            "🧠 Initializing AI-powered search pipeline...", "info"
        )

        # Use the existing OmicsOracle pipeline to process the query
        result = await process_search_query(request.query, request.max_results)

        search_time = time.time() - search_start_time
        await log_to_frontend(
            f"✅ Search completed in {search_time:.2f}s", "success"
        )
        await log_to_frontend(
            f"📊 Found {len(result['datasets'])} relevant datasets", "success"
        )

        return SearchResponse(
            query=request.query,
            results=result["datasets"],
            total_found=len(result["datasets"]),
            search_time=search_time,
            timestamp=time.time(),
        )

    except Exception as e:
        await log_to_frontend(f"❌ Search failed: {str(e)}", "error")
        logger.error(f"❌ Search failed: {e}")
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")


async def process_search_query(
    query: str, max_results: int = 10
) -> Dict[str, Any]:
    """Process search query using the existing OmicsOracle pipeline"""
    try:
        # Check if pipeline is available
        if not pipeline:
            raise Exception("Pipeline not initialized")

        logger.info(f"🔍 Starting pipeline query processing for: {query}")
        await log_to_frontend("🔍 Starting pipeline query processing...", "info")

        await log_to_frontend("🧬 Connecting to NCBI GEO database...", "info")

        # Use the pipeline's process_query method (it's async!)
        # This will handle GEO query preparation, extraction, and AI summary
        query_result = await pipeline.process_query(
            query, max_results=max_results
        )

        await log_to_frontend(
            f"📊 Pipeline results: {len(query_result.geo_ids)} GEO IDs found",
            "success",
        )
        await log_to_frontend(
            f"🔍 DEBUG: Metadata entries: {len(query_result.metadata)}", "debug"
        )
        await log_to_frontend(
            f"🔍 DEBUG: AI summaries keys: {list(query_result.ai_summaries.keys()) if query_result.ai_summaries else 'None'}",
            "debug",
        )
        logger.info(
            f"📊 Pipeline results: {len(query_result.geo_ids)} GEO IDs found, {len(query_result.metadata)} metadata entries"
        )

        # Extract and format the results
        datasets = []

        await log_to_frontend(
            "🔬 Processing metadata and generating AI insights...", "info"
        )

        # Check if we have GEO IDs (even without metadata)
        if query_result.geo_ids:
            for i, geo_id in enumerate(query_result.geo_ids[:max_results]):
                await log_to_frontend(
                    f"📋 Processing dataset {i + 1}/{min(len(query_result.geo_ids), max_results)}: {geo_id}",
                    "debug",
                )
                # Get metadata if available, otherwise use defaults
                metadata = {}
                if i < len(query_result.metadata):
                    metadata = query_result.metadata[i] or {}

                await log_to_frontend(
                    f"🔍 DEBUG: {geo_id} metadata keys: {list(metadata.keys()) if metadata else 'Empty'}",
                    "debug",
                )

                # Clean up organism field
                organism = metadata.get("organism", "").strip()
                if not organism or organism.lower() == "unknown":
                    organism = "Homo sapiens"

                # Get platform info (skip if Unknown platform)
                platform = metadata.get("platform", "").strip()
                if not platform or platform == "Unknown platform":
                    platform = None  # Don't display platform if unknown

                # Normalize relevance score to 0-1 range
                raw_score = metadata.get("relevance_score", 2.0)
                if raw_score > 1.0:
                    # Assume it's out of 5 or similar scale
                    relevance_score = min(raw_score / 5.0, 1.0)
                else:
                    relevance_score = raw_score

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
                ai_insights = "AI analysis unavailable - no metadata to analyze"
                if query_result.ai_summaries:
                    # Check individual summaries first
                    if "individual_summaries" in query_result.ai_summaries:
                        for summary_item in query_result.ai_summaries[
                            "individual_summaries"
                        ]:
                            if summary_item.get("accession") == geo_id:
                                ai_insights = summary_item.get(
                                    "summary", ai_insights
                                )
                                break
                    # Fallback to brief overview or batch summary
                    if (
                        ai_insights
                        == "AI analysis unavailable - no metadata to analyze"
                    ):
                        # Generate dataset-specific insight based on available metadata
                        if metadata.get("title") and metadata.get("summary"):
                            title = metadata.get("title", "").lower()
                            summary_snippet = metadata.get("summary", "")
                            ai_insights = f"Dataset-specific analysis: This study ({geo_id}) investigates {title}. The research examines {summary_snippet}"
                        elif "brief_overview" in query_result.ai_summaries:
                            overview = query_result.ai_summaries[
                                "brief_overview"
                            ]
                            # If it's a dict, extract the overview text
                            if (
                                isinstance(overview, dict)
                                and "overview" in overview
                            ):
                                ai_insights = (
                                    f"General analysis: {overview['overview']}"
                                )
                            else:
                                ai_insights = (
                                    f"General analysis: {str(overview)}"
                                )
                        elif "batch_summary" in query_result.ai_summaries:
                            batch_summary = query_result.ai_summaries[
                                "batch_summary"
                            ]
                            # If it's a dict, extract meaningful text
                            if isinstance(batch_summary, dict):
                                ai_insights = f"Batch analysis: {str(batch_summary.get('summary', batch_summary))}"
                            else:
                                ai_insights = (
                                    f"Batch analysis: {str(batch_summary)}"
                                )

                dataset_info = {
                    "geo_id": geo_id,
                    "title": metadata.get("title", "Title not available"),
                    "summary": metadata.get(
                        "summary",
                        "Summary not available - metadata could not be retrieved from NCBI GEO",
                    ),
                    "organism": organism,
                    "sample_count": metadata.get(
                        "sample_count", None
                    ),  # Use None instead of 0
                    "platform": platform,  # Can be None
                    "publication_date": pub_date,
                    "study_type": metadata.get(
                        "type", "Study type not specified"
                    ),
                    "ai_insights": ai_insights,
                    "relevance_score": relevance_score,
                }
                datasets.append(dataset_info)

            logger.info(f"✅ Successfully formatted {len(datasets)} datasets")
            await log_to_frontend(
                f"✅ Successfully processed {len(datasets)} datasets", "success"
            )

        # Return empty results if nothing found - no fallback to mock data
        if not datasets:
            logger.warning("⚠️ No datasets found from pipeline")
            return {
                "datasets": [],
                "query": query,
                "ai_insights": f"No results found for '{query}'. Please try a different search term.",
            }

        # Create AI insights message
        ai_insights = (
            f"Found {len(datasets)} biomedical datasets for '{query}'."
        )
        if query_result.intent:
            ai_insights += f" Detected intent: {query_result.intent}."
        if query_result.duration:
            ai_insights += f" Search completed in {query_result.duration:.2f}s."
        else:
            ai_insights += " Search completed successfully."

        # Add note about metadata if some failed
        if len(query_result.geo_ids) > len(
            [m for m in query_result.metadata if m]
        ):
            ai_insights += " Note: Some datasets have pending metadata (common for recent submissions)."

        await log_to_frontend("🎯 Query processing complete!", "success")

        return {
            "datasets": datasets,
            "query": query,
            "ai_insights": ai_insights,
        }

    except Exception as e:
        # Error in real pipeline - return actual error, no mock fallback
        logger.error(f"❌ Error processing search query: {e}")
        raise Exception(f"Pipeline processing failed: {e}")


@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "pipeline_available": pipeline is not None,
        "message": "Futuristic interface ready",
    }


@app.websocket("/ws/monitor")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for live query monitoring"""
    await manager.connect(websocket)
    try:
        await log_to_frontend("🔄 Live monitoring connected", "success")
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8001,
        reload=True,
        log_level="info",
    )
