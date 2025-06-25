#!/usr/bin/env python3
"""
Original/First Web Interface for OmicsOracle
============================================

This is the very first web interface created for OmicsOracle.
It's a standalone FastAPI application that serves static HTML with embedded JavaScript.

Features:
- Simple HTML interface with embedded CSS/JS
- Direct FastAPI backend integration
- WebSocket support for real-time updates
- Basic search functionality
- Results visualization
- Export capabilities

To run this interface:
    python web-interface-original/main.py

Then open: http://localhost:8001
"""

import asyncio
import json
import logging
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List

import uvicorn
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse

# Add parent directories to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    # OmicsOracle imports
    from omics_oracle.core.config import Config
    from omics_oracle.pipeline import OmicsOraclePipeline, ResultFormat

    OMICS_ORACLE_AVAILABLE = True
except ImportError as e:
    print(f"⚠️  OmicsOracle modules not available: {e}")
    print("   Running in demo mode with mock data")
    OMICS_ORACLE_AVAILABLE = False

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="OmicsOracle - Original Web Interface",
    description="The first web interface for OmicsOracle",
    version="1.0.0",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global state
pipeline = None
config = None
active_queries = {}


# WebSocket Connection Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.query_subscribers: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(
            f"WebSocket connected. Total connections: {len(self.active_connections)}"
        )

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        # Remove from query subscribers
        for query_id, connections in self.query_subscribers.items():
            if websocket in connections:
                connections.remove(websocket)
        logger.info(
            f"WebSocket disconnected. Total connections: {len(self.active_connections)}"
        )

    async def send_personal_message(self, message: str, websocket: WebSocket):
        try:
            await websocket.send_text(message)
        except Exception as e:
            logger.error(f"Error sending personal message: {e}")

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                logger.error(f"Error broadcasting message: {e}")

    async def send_to_query_subscribers(self, query_id: str, message: str):
        if query_id in self.query_subscribers:
            for connection in self.query_subscribers[query_id]:
                try:
                    await connection.send_text(message)
                except Exception as e:
                    logger.error(f"Error sending to query subscriber: {e}")

    def subscribe_to_query(self, query_id: str, websocket: WebSocket):
        if query_id not in self.query_subscribers:
            self.query_subscribers[query_id] = []
        self.query_subscribers[query_id].append(websocket)


manager = ConnectionManager()


# Initialize pipeline
async def initialize_pipeline():
    global pipeline, config

    if not OMICS_ORACLE_AVAILABLE:
        logger.info("OmicsOracle not available, running in demo mode")
        return

    try:
        logger.info("Initializing OmicsOracle pipeline...")
        config = Config()
        pipeline = OmicsOraclePipeline(config)
        logger.info("Pipeline initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize pipeline: {e}")
        pipeline = None


# Startup event
@app.on_event("startup")
async def startup_event():
    await initialize_pipeline()


# Health check endpoint
@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "pipeline_initialized": pipeline is not None,
        "config_loaded": config is not None,
        "omics_oracle_available": OMICS_ORACLE_AVAILABLE,
        "interface": "original",
        "timestamp": datetime.now().isoformat(),
    }


# Root endpoint - serve the original HTML interface
@app.get("/", response_class=HTMLResponse)
async def read_root():
    html_file = Path(__file__).parent / "index.html"

    if html_file.exists():
        return FileResponse(html_file)
    else:
        # Fallback minimal HTML if original file not found
        return HTMLResponse(
            """
        <!DOCTYPE html>
        <html>
        <head>
            <title>OmicsOracle - Original Interface</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .error { color: red; }
            </style>
        </head>
        <body>
            <h1>🧬 OmicsOracle - Original Web Interface</h1>
            <div class="error">
                <p>Original HTML file not found. Please ensure the file exists at:</p>
                <code>index.html</code>
            </div>
        </body>
        </html>
        """
        )


# Search endpoint
@app.post("/api/search")
async def search_datasets(request: dict):
    try:
        query = request.get("query", "")
        max_results = request.get("max_results", 10)

        if not query:
            raise HTTPException(status_code=400, detail="Query is required")

        query_id = str(uuid.uuid4())

        # Store query in active queries
        active_queries[query_id] = {
            "query": query,
            "status": "running",
            "start_time": datetime.now().isoformat(),
            "results": None,
        }

        # Notify WebSocket clients
        await manager.broadcast(
            json.dumps(
                {"type": "query_started", "query_id": query_id, "query": query}
            )
        )

        if OMICS_ORACLE_AVAILABLE and pipeline:
            try:
                # Run the actual search
                results = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: pipeline.search(
                        query,
                        max_results=max_results,
                        output_format=ResultFormat.STRUCTURED,
                    ),
                )

                # Process results
                if hasattr(results, "results") and results.results:
                    metadata = []
                    for result in results.results[:max_results]:
                        metadata.append(
                            {
                                "id": getattr(result, "id", "unknown"),
                                "title": getattr(result, "title", "No title"),
                                "summary": getattr(
                                    result, "summary", "No summary available"
                                ),
                                "organism": getattr(
                                    result, "organism", "Unknown"
                                ),
                                "sample_count": getattr(
                                    result, "sample_count", 0
                                ),
                                "platform": getattr(
                                    result, "platform", "Unknown"
                                ),
                                "relevance_score": getattr(
                                    result, "relevance_score", 0.0
                                ),
                            }
                        )

                    response_data = {
                        "metadata": metadata,
                        "total_count": len(metadata),
                        "status": "completed",
                        "query_id": query_id,
                        "query": query,
                        "execution_time": "N/A",
                    }
                else:
                    response_data = {
                        "metadata": [],
                        "total_count": 0,
                        "status": "completed",
                        "query_id": query_id,
                        "query": query,
                        "execution_time": "N/A",
                    }

                # Update active queries
                active_queries[query_id]["status"] = "completed"
                active_queries[query_id]["results"] = response_data

                # Notify WebSocket clients
                await manager.broadcast(
                    json.dumps(
                        {
                            "type": "query_completed",
                            "query_id": query_id,
                            "results": response_data,
                        }
                    )
                )

                return response_data

            except Exception as e:
                logger.error(f"Search error: {e}")
                error_response = {
                    "metadata": [],
                    "total_count": 0,
                    "status": "error",
                    "query_id": query_id,
                    "query": query,
                    "error": str(e),
                }

                active_queries[query_id]["status"] = "error"
                active_queries[query_id]["error"] = str(e)

                await manager.broadcast(
                    json.dumps(
                        {
                            "type": "query_error",
                            "query_id": query_id,
                            "error": str(e),
                        }
                    )
                )

                return error_response
        else:
            # Demo mode - return mock data
            mock_data = {
                "metadata": [
                    {
                        "id": "GSE123456",
                        "title": f"Mock dataset for query: {query}",
                        "summary": f"This is a mock result for demonstration purposes. Original query: {query}",
                        "organism": "Homo sapiens",
                        "sample_count": 24,
                        "platform": "GPL570",
                        "relevance_score": 0.85,
                    }
                ],
                "total_count": 1,
                "status": "completed",
                "query_id": query_id,
                "query": query,
                "execution_time": "0.5s",
                "demo_mode": True,
            }

            active_queries[query_id]["status"] = "completed"
            active_queries[query_id]["results"] = mock_data

            await manager.broadcast(
                json.dumps(
                    {
                        "type": "query_completed",
                        "query_id": query_id,
                        "results": mock_data,
                    }
                )
            )

            return mock_data

    except Exception as e:
        logger.error(f"Search endpoint error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Query status endpoint
@app.get("/api/query/{query_id}/status")
def get_query_status(query_id: str):
    if query_id in active_queries:
        return active_queries[query_id]
    else:
        raise HTTPException(status_code=404, detail="Query not found")


# WebSocket endpoint for real-time updates
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)

            if message.get("action") == "ping":
                await manager.send_personal_message("pong", websocket)
            elif message.get("action") == "subscribe":
                query_id = message.get("query_id")
                if query_id:
                    manager.subscribe_to_query(query_id, websocket)

    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)


if __name__ == "__main__":
    print("🧬 Starting OmicsOracle - Original Web Interface")
    print("=" * 50)
    print(f"Interface URL: http://localhost:8001")
    print(f"Health Check: http://localhost:8001/health")
    print(f"OmicsOracle Available: {OMICS_ORACLE_AVAILABLE}")
    print("=" * 50)

    uvicorn.run(
        "main:app", host="0.0.0.0", port=8001, reload=False, log_level="info"
    )
