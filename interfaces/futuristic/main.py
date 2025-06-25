"""
Futuristic Interface for OmicsOracle - Next Generation Research Platform

This module implements a cutting-edge interface with:
- Real-time agent-based processing
- Advanced visualization capabilities
- WebSocket-powered live updates
- Multi-modal search and analysis
- AI-powered insights and recommendations

The existing interface remains fully functional as a fallback.
"""

import logging

# Import existing OmicsOracle components
import sys
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    HTTPException,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

from agents.analysis_agent import AnalysisAgent

# Import our new agent system
from agents.orchestrator import AgentOrchestrator
from agents.search_agent import SearchAgent
from agents.visualization_agent import VisualizationAgent
from models.futuristic_models import (
    AgentMessage,
    AgentStatus,
    FuturisticSearchRequest,
    JobStatus,
    SearchJob,
    SearchResponse,
    SystemMetrics,
)
from services.websocket_manager import WebSocketManager

from src.omics_oracle.core.config import Config
from src.omics_oracle.pipeline import OmicsOracle

logger = logging.getLogger(__name__)

# Global application state
orchestrator: Optional[AgentOrchestrator] = None
websocket_manager: Optional[WebSocketManager] = None
legacy_pipeline: Optional[OmicsOracle] = None  # Fallback to existing system


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management with graceful fallback"""
    global orchestrator, websocket_manager, legacy_pipeline

    try:
        # Initialize futuristic components
        logger.info("[LAUNCH] Initializing Futuristic Interface...")

        # Initialize WebSocket manager
        websocket_manager = WebSocketManager()

        # Initialize agent orchestrator
        orchestrator = AgentOrchestrator()

        # Register specialized agents
        search_agent = SearchAgent("search-agent-001")
        analysis_agent = AnalysisAgent("analysis-agent-001")
        viz_agent = VisualizationAgent("viz-agent-001")

        await orchestrator.register_agent(search_agent)
        await orchestrator.register_agent(analysis_agent)
        await orchestrator.register_agent(viz_agent)

        # Start agent orchestrator
        await orchestrator.start()

        # Initialize legacy pipeline as fallback
        config = Config()
        legacy_pipeline = OmicsOracle(config)

        logger.info("[OK] Futuristic Interface initialized successfully")
        logger.info("[SECURITY] Legacy interface available as fallback")

        yield

    except Exception as e:
        logger.error(f"[ERROR] Failed to initialize futuristic interface: {e}")
        logger.info("[REFRESH] Falling back to legacy interface only")

        # Ensure legacy pipeline is available
        if not legacy_pipeline:
            config = Config()
            legacy_pipeline = OmicsOracle(config)

        yield

    finally:
        # Cleanup
        if orchestrator:
            await orchestrator.stop()
        if websocket_manager:
            await websocket_manager.cleanup()


# Create FastAPI app with lifespan management
app = FastAPI(
    title="OmicsOracle Futuristic Interface",
    description="Next-generation biomedical research platform with AI agents",
    version="2.0.0",
    lifespan=lifespan,
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
static_path = Path(__file__).parent / "static"
static_path.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_path)), name="static")

# Templates
templates_path = Path(__file__).parent / "templates"
templates_path.mkdir(exist_ok=True)
templates = Jinja2Templates(directory=str(templates_path))


# Dependency to check if futuristic mode is available
async def get_mode_status() -> Dict[str, bool]:
    """Check availability of different interface modes"""
    return {
        "futuristic_available": orchestrator is not None
        and orchestrator.is_running,
        "legacy_available": legacy_pipeline is not None,
        "agents_active": orchestrator.active_agent_count if orchestrator else 0,
    }


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
        <script src="https://cdn.tailwindcss.com"></script>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <script src="https://d3js.org/d3.v7.min.js"></script>
        <style>
            .gradient-bg {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            }
            .glass-effect {
                background: rgba(255, 255, 255, 0.1);
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255, 255, 255, 0.2);
            }
            .agent-pulse {
                animation: pulse 2s infinite;
            }
            @keyframes pulse {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.7; }
            }
        </style>
    </head>
    <body class="gradient-bg min-h-screen">
        <div id="app" class="container mx-auto px-4 py-8">
            <!-- Header -->
            <header class="text-center mb-12">
                <h1 class="text-6xl font-bold text-white mb-4">
                    [BIOMEDICAL] OmicsOracle
                </h1>
                <p class="text-xl text-gray-200 mb-6">
                    Next-Generation Biomedical Research Intelligence Platform
                </p>
                <div id="mode-indicator" class="glass-effect rounded-lg p-4 inline-block">
                    <div class="flex items-center space-x-4">
                        <div id="futuristic-status" class="flex items-center">
                            <div class="w-3 h-3 rounded-full bg-green-400 agent-pulse mr-2"></div>
                            <span class="text-white">Futuristic Mode Active</span>
                        </div>
                        <div id="legacy-status" class="flex items-center">
                            <div class="w-3 h-3 rounded-full bg-blue-400 mr-2"></div>
                            <span class="text-white">Legacy Fallback Ready</span>
                        </div>
                    </div>
                </div>
            </header>

            <!-- Main Interface -->
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
                <!-- Left Panel: Search & Agents -->
                <div class="lg:col-span-2">
                    <!-- Smart Search -->
                    <div class="glass-effect rounded-xl p-6 mb-8">
                        <h2 class="text-2xl font-bold text-white mb-4">[SEARCH] Intelligent Search</h2>
                        <div class="space-y-4">
                            <input
                                id="smart-search"
                                type="text"
                                placeholder="Ask anything about biomedical research..."
                                class="w-full p-4 rounded-lg bg-white/20 text-white placeholder-gray-300 border border-white/30 focus:border-white/60 focus:outline-none"
                            >
                            <div class="flex space-x-4">
                                <button id="search-btn" class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-lg transition-colors">
                                    [LAUNCH] AI Search
                                </button>
                                <button id="fallback-btn" class="bg-gray-600 hover:bg-gray-700 text-white px-6 py-3 rounded-lg transition-colors">
                                    [SECURITY] Legacy Search
                                </button>
                            </div>
                        </div>
                    </div>

                    <!-- Agent Dashboard -->
                    <div class="glass-effect rounded-xl p-6">
                        <h2 class="text-2xl font-bold text-white mb-4">[AGENT] AI Agents</h2>
                        <div id="agent-status" class="space-y-4">
                            <!-- Agent statuses will be populated dynamically -->
                        </div>
                    </div>
                </div>

                <!-- Right Panel: Live Results & Visualizations -->
                <div class="lg:col-span-1">
                    <!-- Live Results -->
                    <div class="glass-effect rounded-xl p-6 mb-8">
                        <h2 class="text-2xl font-bold text-white mb-4">[CHART] Live Results</h2>
                        <div id="live-results" class="space-y-4 max-h-96 overflow-y-auto">
                            <div class="text-gray-300 text-center py-8">
                                Ready for intelligent search...
                            </div>
                        </div>
                    </div>

                    <!-- System Monitor -->
                    <div class="glass-effect rounded-xl p-6">
                        <h2 class="text-2xl font-bold text-white mb-4">[FAST] System Monitor</h2>
                        <div id="system-stats" class="space-y-2">
                            <div class="flex justify-between text-white">
                                <span>Active Agents:</span>
                                <span id="active-agents">0</span>
                            </div>
                            <div class="flex justify-between text-white">
                                <span>Processed Queries:</span>
                                <span id="processed-queries">0</span>
                            </div>
                            <div class="flex justify-between text-white">
                                <span>Response Time:</span>
                                <span id="response-time">--</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Visualization Panel -->
            <div class="mt-8">
                <div class="glass-effect rounded-xl p-6">
                    <h2 class="text-2xl font-bold text-white mb-4">[GRAPH] Interactive Visualizations</h2>
                    <div id="visualization-container" class="h-96 bg-white/10 rounded-lg flex items-center justify-center">
                        <div class="text-gray-300 text-center">
                            <div class="text-4xl mb-4">[CHART]</div>
                            <div>Visualizations will appear here after search</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <script src="/static/js/futuristic-interface.js"></script>
    </body>
    </html>
    """


@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    """WebSocket endpoint for real-time communication"""
    if not websocket_manager:
        await websocket.close(code=1011, reason="Futuristic mode not available")
        return

    await websocket_manager.connect(websocket, client_id)

    try:
        while True:
            # Receive message from client
            data = await websocket.receive_json()

            # Process message through agent orchestrator
            if orchestrator and orchestrator.is_running:
                response = await orchestrator.process_user_message(
                    data, client_id
                )
                await websocket_manager.send_personal_message(
                    response, client_id
                )
            else:
                # Fallback response
                fallback_response = {
                    "type": "fallback_notification",
                    "message": "Using legacy processing mode",
                    "data": await process_with_legacy(data),
                }
                await websocket_manager.send_personal_message(
                    fallback_response, client_id
                )

    except WebSocketDisconnect:
        await websocket_manager.disconnect(websocket, client_id)


@app.post("/api/v2/search")
async def futuristic_search(
    request: FuturisticSearchRequest,
    background_tasks: BackgroundTasks,
    mode_status: Dict[str, bool] = Depends(get_mode_status),
):
    """Advanced search with AI agents or fallback to legacy"""

    if mode_status["futuristic_available"]:
        # Use futuristic agent-based search
        search_job = SearchJob(
            id=str(uuid.uuid4()),
            query=request.query,
            search_type=request.search_type,
            filters=request.filters,
            status=JobStatus.PROCESSING,
        )

        # Start background processing
        background_tasks.add_task(orchestrator.process_search_job, search_job)

        return SearchResponse(
            job_id=search_job.id,
            status=JobStatus.PROCESSING,
            message="AI agents are processing your request",
            estimated_time=30,
            mode="futuristic",
        )
    else:
        # Fallback to legacy search
        logger.info("Using legacy search as fallback")
        return await legacy_search(request)


@app.get("/api/v2/search/{job_id}")
async def get_search_results(job_id: str):
    """Get search results by job ID"""

    if orchestrator:
        result = await orchestrator.get_job_result(job_id)
        if result:
            return result

    # If not found in futuristic system, check legacy
    return {"error": "Job not found", "suggestion": "Try legacy search"}


@app.get("/api/v2/health")
async def health_check():
    """Health check endpoint with mode status"""
    status = await get_mode_status()

    return {
        "status": "healthy",
        "timestamp": time.time(),
        "modes": status,
        "message": "Futuristic interface with legacy fallback ready",
    }


async def legacy_search(request: FuturisticSearchRequest) -> SearchResponse:
    """Fallback to legacy search system"""
    try:
        # Use existing pipeline
        if legacy_pipeline:
            # Process query with legacy system
            # result = await legacy_pipeline.process_query(request.query)
            await legacy_pipeline.process_query(request.query)

            return SearchResponse(
                job_id=str(uuid.uuid4()),
                status=JobStatus.COMPLETED,
                results=[],  # Convert result to SearchResult format as needed
                message="Processed with legacy system",
                mode="legacy",
            )
    except Exception as e:
        logger.error(f"Legacy search failed: {e}")
        raise HTTPException(
            status_code=500, detail="Both futuristic and legacy search failed"
        )

    # Fallback if no pipeline available
    raise HTTPException(status_code=503, detail="No search system available")


async def process_with_legacy(data: dict) -> dict:
    """Process data with legacy system"""
    try:
        if legacy_pipeline and data.get("type") == "search":
            results = await legacy_pipeline.search(
                query=data.get("query", ""), filters=data.get("filters", {})
            )
            return {
                "type": "search_results",
                "results": results,
                "mode": "legacy",
            }
    except Exception as e:
        logger.error(f"Legacy processing failed: {e}")
        return {"type": "error", "message": "Processing failed in both modes"}


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8001,  # Different port from legacy interface
        reload=True,
        log_level="info",
    )
