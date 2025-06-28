"""
Enhanced Futuristic Interface for OmicsOracle - Next Generation Research Platform

This module implements a cutting-edge interface that integrates with the Clean Architecture
backend for advanced search, analysis, and visualization capabilities.
"""

import asyncio
import logging
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
import uvicorn
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Add the main project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

# Environment configuration
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
INTERFACE_PORT = int(os.getenv("INTERFACE_PORT", "8001"))
DEBUG_MODE = os.getenv("DEBUG_MODE", "false").lower() == "true"


class EnhancedSearchRequest(BaseModel):
    """Enhanced search request with v2 API features"""

    query: str = Field(..., description="Search query for biomedical datasets")
    filters: Optional[Dict[str, Any]] = Field(None, description="Search filters")
    include_metadata: bool = Field(True, description="Include enhanced metadata")
    max_results: int = Field(10, description="Maximum number of results")
    search_type: str = Field("enhanced", description="Search type: basic, enhanced, or comprehensive")


class EnhancedSearchResponse(BaseModel):
    """Enhanced search response with v2 API features"""

    query: str
    results: List[Dict[str, Any]]
    total_found: int
    search_time: float
    metadata: Optional[Dict[str, Any]] = None
    timestamp: float
    api_version: str = "2.0"


class WebSocketManager:
    """Enhanced WebSocket manager for real-time communication"""

    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.client_data: Dict[str, Dict[str, Any]] = {}

    async def connect(self, websocket: WebSocket, client_id: str):
        """Connect a new WebSocket client"""
        await websocket.accept()
        self.active_connections[client_id] = websocket
        self.client_data[client_id] = {"connected_at": asyncio.get_event_loop().time()}
        logger.info(f"WebSocket client {client_id} connected")

    def disconnect(self, client_id: str):
        """Disconnect a WebSocket client"""
        if client_id in self.active_connections:
            del self.active_connections[client_id]
        if client_id in self.client_data:
            del self.client_data[client_id]
        logger.info(f"WebSocket client {client_id} disconnected")

    async def send_personal_message(self, message: dict, client_id: str):
        """Send a message to a specific client"""
        if client_id in self.active_connections:
            try:
                await self.active_connections[client_id].send_json(message)
            except Exception as e:
                logger.error(f"Error sending message to {client_id}: {e}")
                self.disconnect(client_id)

    async def broadcast(self, message: dict):
        """Broadcast a message to all connected clients"""
        if not self.active_connections:
            return

        disconnected_clients = []
        for client_id, websocket in self.active_connections.items():
            try:
                await websocket.send_json(message)
            except Exception as e:
                logger.error(f"Error broadcasting to {client_id}: {e}")
                disconnected_clients.append(client_id)

        # Clean up disconnected clients
        for client_id in disconnected_clients:
            self.disconnect(client_id)


# Global WebSocket manager
websocket_manager = WebSocketManager()


class BackendClient:
    """HTTP client for Clean Architecture backend"""

    def __init__(self, base_url: str = BACKEND_URL):
        self.base_url = base_url
        self.client = httpx.AsyncClient(timeout=30.0, follow_redirects=True)

    async def health_check(self) -> Dict[str, Any]:
        """Check backend health"""
        try:
            response = await self.client.get(f"{self.base_url}/api/v2/health")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Backend health check failed: {e}")
            return {"status": "error", "message": str(e)}

    async def search_datasets(self, request: EnhancedSearchRequest) -> Dict[str, Any]:
        """Search datasets using v2 API"""
        try:
            if request.search_type == "enhanced":
                endpoint = f"{self.base_url}/api/v2/search/enhanced"
            else:
                endpoint = f"{self.base_url}/api/v2/search"

            response = await self.client.post(endpoint, json=request.dict())
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Search request failed: {e}")
            raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")

    async def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        try:
            response = await self.client.get(f"{self.base_url}/api/v2/system/cache/stats")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Cache stats request failed: {e}")
            return {"error": str(e)}

    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()


# Global backend client
backend_client = BackendClient()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    logger.info("Starting Enhanced Futuristic Interface")

    # Startup
    try:
        # Check backend connectivity
        health = await backend_client.health_check()
        logger.info(f"Backend health: {health}")
    except Exception as e:
        logger.warning(f"Backend connectivity issue: {e}")

    yield

    # Shutdown
    logger.info("Shutting down Enhanced Futuristic Interface")
    await backend_client.close()


# FastAPI app with enhanced configuration
app = FastAPI(
    title="OmicsOracle Enhanced Futuristic Interface",
    description="Next-generation biomedical research platform with Clean Architecture integration",
    version="2.0.0",
    lifespan=lifespan,
    debug=DEBUG_MODE,
)

# Enhanced CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if DEBUG_MODE else ["http://localhost:3000", "http://localhost:8001"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Static files
static_path = Path(__file__).parent / "static"
static_path.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_path)), name="static")


# Dependency for backend client
async def get_backend_client() -> BackendClient:
    return backend_client


# Enhanced API Routes
@app.get("/", response_class=HTMLResponse)
async def home():
    """Enhanced home page with Clean Architecture integration"""
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>OmicsOracle Enhanced Interface</title>
        <link rel="stylesheet" href="/static/css/main.css">
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-date-fns/dist/chartjs-adapter-date-fns.bundle.min.js"></script>
    </head>
    <body>
        <div class="enhanced-interface">
            <header class="header">
                <h1>🧬 OmicsOracle Enhanced Interface</h1>
                <p>Next-Generation Biomedical Research Platform</p>
                <div class="status-indicators">
                    <div class="status-item" id="backend-status">
                        <span class="status-dot"></span>
                        <span>Backend: Checking...</span>
                    </div>
                    <div class="status-item" id="websocket-status">
                        <span class="status-dot"></span>
                        <span>WebSocket: Connecting...</span>
                    </div>
                </div>
            </header>

            <main class="main-content">
                <div class="search-section">
                    <h2>🔍 Enhanced Search</h2>
                    <div class="search-form">
                        <input type="text" id="search-input" placeholder="Enter your research query..." class="search-input">
                        <div class="search-options">
                            <label>
                                <input type="checkbox" id="include-metadata" checked>
                                Include Enhanced Metadata
                            </label>
                            <select id="search-type" class="search-type-select">
                                <option value="enhanced">Enhanced Search</option>
                                <option value="basic">Basic Search</option>
                                <option value="comprehensive">Comprehensive Search</option>
                            </select>
                        </div>
                        <button id="search-btn" class="search-btn">Search Datasets</button>
                    </div>
                </div>

                <div class="results-section" id="results-section" style="display: none;">
                    <h2>📊 Search Results</h2>
                    <div class="results-metadata" id="results-metadata"></div>
                    <div class="results-container" id="results-container"></div>
                </div>

                <div class="system-section">
                    <h2>⚙️ System Status</h2>
                    <div class="system-grid">
                        <div class="system-card">
                            <h3>API Health</h3>
                            <div id="api-health">Checking...</div>
                        </div>
                        <div class="system-card">
                            <h3>Cache Stats</h3>
                            <div id="cache-stats">Loading...</div>
                        </div>
                        <div class="system-card">
                            <h3>Real-time Status</h3>
                            <div id="realtime-status">Initializing...</div>
                        </div>
                    </div>
                </div>
            </main>
        </div>

        <script src="/static/js/futuristic-interface.js"></script>
        <script>
            // Initialize enhanced interface
            document.addEventListener('DOMContentLoaded', function() {
                const interface = new FuturisticInterface();
                interface.initEnhancedFeatures();
            });
        </script>
    </body>
    </html>
    """


@app.post("/api/v2/search/enhanced", response_model=EnhancedSearchResponse)
async def enhanced_search(
    request: EnhancedSearchRequest,
    backend: BackendClient = Depends(get_backend_client),
    background_tasks: BackgroundTasks = BackgroundTasks(),
):
    """Enhanced search with Clean Architecture backend integration"""
    logger.info(f"Enhanced search request: {request.query}")

    try:
        # Send search request to backend
        result = await backend.search_datasets(request)

        # Broadcast search event to WebSocket clients
        background_tasks.add_task(
            websocket_manager.broadcast,
            {
                "type": "search_completed",
                "query": request.query,
                "results_count": len(result.get("datasets", [])),
                "timestamp": asyncio.get_event_loop().time(),
            },
        )

        return EnhancedSearchResponse(
            query=request.query,
            results=result.get("datasets", []),
            total_found=len(result.get("datasets", [])),
            search_time=result.get("search_time", 0.0),
            metadata=result.get("metadata"),
            timestamp=asyncio.get_event_loop().time(),
        )

    except Exception as e:
        logger.error(f"Enhanced search failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v2/health")
async def health_check(backend: BackendClient = Depends(get_backend_client)):
    """Enhanced health check"""
    backend_health = await backend.health_check()

    return {
        "interface_status": "healthy",
        "backend_status": backend_health.get("status", "unknown"),
        "websocket_connections": len(websocket_manager.active_connections),
        "backend_url": BACKEND_URL,
        "version": "2.0.0",
        "timestamp": asyncio.get_event_loop().time(),
    }


@app.get("/api/v2/system/cache/stats")
async def get_cache_stats(backend: BackendClient = Depends(get_backend_client)):
    """Get cache statistics from backend"""
    return await backend.get_cache_stats()


@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    """Enhanced WebSocket endpoint for real-time communication"""
    await websocket_manager.connect(websocket, client_id)

    try:
        # Send welcome message
        await websocket_manager.send_personal_message(
            {
                "type": "connection_established",
                "client_id": client_id,
                "message": "Connected to Enhanced Interface",
                "timestamp": asyncio.get_event_loop().time(),
            },
            client_id,
        )

        while True:
            # Listen for client messages
            data = await websocket.receive_json()

            # Handle different message types
            if data.get("type") == "ping":
                await websocket_manager.send_personal_message(
                    {
                        "type": "pong",
                        "timestamp": asyncio.get_event_loop().time(),
                    },
                    client_id,
                )
            elif data.get("type") == "subscribe":
                # Handle subscription to specific events
                await websocket_manager.send_personal_message(
                    {"type": "subscribed", "event": data.get("event")},
                    client_id,
                )

    except WebSocketDisconnect:
        websocket_manager.disconnect(client_id)
    except Exception as e:
        logger.error(f"WebSocket error for client {client_id}: {e}")
        websocket_manager.disconnect(client_id)


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=INTERFACE_PORT,
        reload=DEBUG_MODE,
        log_level="info" if DEBUG_MODE else "warning",
    )
