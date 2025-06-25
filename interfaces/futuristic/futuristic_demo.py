#!/usr/bin/env python3
"""
Simplified Futuristic Interface Startup

This script provides a working demonstration of the futuristic interface
with fallback to the legacy system, without complex agent imports.
"""

import asyncio
import logging
import sys
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

# Add paths for legacy system imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.omics_oracle.core.config import Config
from src.omics_oracle.pipeline import OmicsOracle

logger = logging.getLogger(__name__)

# Global state
legacy_pipeline: Optional[OmicsOracle] = None
startup_time = None


# Simplified Models
class SearchRequest(BaseModel):
    query: str = Field(..., description="Search query")
    search_type: str = Field(default="basic", description="Search type")
    max_results: int = Field(default=50, description="Maximum results")


class SearchResponse(BaseModel):
    job_id: str
    status: str
    query: Optional[str] = None
    results: List[Dict[str, Any]] = Field(default_factory=list)
    total_results: int = 0
    processing_time: Optional[float] = None
    message: str = ""
    mode: str = "futuristic"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan with fallback initialization"""
    global legacy_pipeline, startup_time

    try:
        logger.info("[LAUNCH] Starting Futuristic Interface (Simplified Demo)")

        # Initialize legacy pipeline as fallback
        config = Config()
        legacy_pipeline = OmicsOracle(config)

        startup_time = asyncio.get_event_loop().time()

        logger.info("[OK] Futuristic Interface initialized successfully")
        logger.info("[SECURITY] Legacy pipeline available as processing backend")

        yield

    except Exception as e:
        logger.error(f"[ERROR] Initialization failed: {e}")
        logger.info("[REFRESH] Running in limited mode")
        yield

    finally:
        # Cleanup
        if legacy_pipeline:
            await legacy_pipeline.close()


# Create FastAPI app
app = FastAPI(
    title="OmicsOracle Futuristic Interface (Demo)",
    description="Next-generation biomedical research platform",
    version="2.0.0-demo",
    lifespan=lifespan,
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", response_class=HTMLResponse)
async def futuristic_interface():
    """Serve the futuristic interface demo"""
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>OmicsOracle - Futuristic Research Platform (Demo)</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <style>
            .gradient-bg {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            }
            .glass-effect {
                background: rgba(255, 255, 255, 0.1);
                backdrop-filter: blur(10px);
                border: 1px solid rgba(255, 255, 255, 0.2);
            }
            .pulse-animation {
                animation: pulse 2s infinite;
            }
        </style>
    </head>
    <body class="gradient-bg min-h-screen">
        <div class="container mx-auto px-4 py-8">
            <!-- Header -->
            <header class="text-center mb-12">
                <h1 class="text-6xl font-bold text-white mb-4">
                    [BIOMEDICAL] OmicsOracle
                </h1>
                <p class="text-xl text-gray-200 mb-6">
                    Futuristic Research Platform (Demo)
                </p>
                <div class="glass-effect rounded-lg p-4 inline-block">
                    <div class="flex items-center space-x-4">
                        <div class="flex items-center">
                            <div class="w-3 h-3 rounded-full bg-green-400 pulse-animation mr-2"></div>
                            <span class="text-white">Futuristic Mode Active</span>
                        </div>
                        <div class="flex items-center">
                            <div class="w-3 h-3 rounded-full bg-blue-400 mr-2"></div>
                            <span class="text-white">Legacy Fallback Ready</span>
                        </div>
                    </div>
                </div>
            </header>

            <!-- Main Interface -->
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
                <!-- Search Panel -->
                <div class="lg:col-span-2">
                    <div class="glass-effect rounded-xl p-6 mb-8">
                        <h2 class="text-2xl font-bold text-white mb-4">[SEARCH] Intelligent Search</h2>
                        <div class="space-y-4">
                            <input
                                id="search-input"
                                type="text"
                                placeholder="Ask anything about biomedical research..."
                                class="w-full p-4 rounded-lg bg-white/20 text-white placeholder-gray-300 border border-white/30 focus:border-white/60 focus:outline-none"
                            >
                            <div class="flex space-x-4">
                                <button onclick="performSearch()" class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-lg transition-colors">
                                    [LAUNCH] Futuristic Search
                                </button>
                                <button onclick="showDemo()" class="bg-purple-600 hover:bg-purple-700 text-white px-6 py-3 rounded-lg transition-colors">
                                    [SPARKLE] Demo Features
                                </button>
                            </div>
                        </div>
                    </div>

                    <!-- Results Panel -->
                    <div class="glass-effect rounded-xl p-6">
                        <h2 class="text-2xl font-bold text-white mb-4">[CHART] Results</h2>
                        <div id="results-container" class="space-y-4 max-h-96 overflow-y-auto">
                            <div class="text-gray-300 text-center py-8">
                                <div class="text-4xl mb-4">[ANALYSIS]</div>
                                <div>Ready for intelligent search...</div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Info Panel -->
                <div>
                    <div class="glass-effect rounded-xl p-6 mb-8">
                        <h2 class="text-2xl font-bold text-white mb-4">[TARGET] Features</h2>
                        <div class="space-y-3 text-gray-200">
                            <div class="flex items-center">
                                <span class="text-green-400 mr-2">[CHECK]</span>
                                Futuristic Interface
                            </div>
                            <div class="flex items-center">
                                <span class="text-green-400 mr-2">[CHECK]</span>
                                Legacy Fallback
                            </div>
                            <div class="flex items-center">
                                <span class="text-blue-400 mr-2">[REFRESH]</span>
                                Real-time Processing
                            </div>
                            <div class="flex items-center">
                                <span class="text-purple-400 mr-2">[AGENT]</span>
                                AI-Powered Insights
                            </div>
                        </div>
                    </div>

                    <div class="glass-effect rounded-xl p-6">
                        <h2 class="text-2xl font-bold text-white mb-4">[FAST] Status</h2>
                        <div id="status-info" class="space-y-2 text-gray-200">
                            <div class="flex justify-between">
                                <span>Interface:</span>
                                <span class="text-green-400">Active</span>
                            </div>
                            <div class="flex justify-between">
                                <span>Mode:</span>
                                <span class="text-blue-400">Futuristic</span>
                            </div>
                            <div class="flex justify-between">
                                <span>Fallback:</span>
                                <span class="text-green-400">Ready</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <script>
            async function performSearch() {
                const query = document.getElementById('search-input').value;
                if (!query.trim()) {
                    alert('Please enter a search query');
                    return;
                }

                const resultsContainer = document.getElementById('results-container');
                resultsContainer.innerHTML = '<div class="text-gray-300 text-center py-8">[SEARCH] Searching...</div>';

                try {
                    const response = await fetch('/api/v2/search', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            query: query,
                            search_type: 'intelligent',
                            max_results: 10
                        })
                    });

                    const result = await response.json();

                    if (response.ok) {
                        displayResults(result);
                    } else {
                        resultsContainer.innerHTML = `<div class="text-red-400 text-center py-8">[ERROR] Error: ${result.detail || 'Search failed'}</div>`;
                    }
                } catch (error) {
                    resultsContainer.innerHTML = '<div class="text-red-400 text-center py-8">[ERROR] Network error</div>';
                }
            }

            function displayResults(result) {
                const resultsContainer = document.getElementById('results-container');
                resultsContainer.innerHTML = `
                    <div class="bg-white/10 rounded-lg p-4 mb-4">
                        <div class="text-green-400 font-bold">[OK] Search Completed</div>
                        <div class="text-gray-300 mt-2">
                            <div>Job ID: ${result.job_id}</div>
                            <div>Status: ${result.status}</div>
                            <div>Mode: ${result.mode}</div>
                            <div>Message: ${result.message}</div>
                        </div>
                    </div>
                `;
            }

            function showDemo() {
                alert('[SUCCESS] Futuristic Interface Demo Features:\\n\\n' +
                      '[LAUNCH] Next-generation UI design\\n' +
                      '[AGENT] AI-powered processing\\n' +
                      '[SECURITY] Automatic fallback to legacy system\\n' +
                      '[FAST] Real-time status updates\\n' +
                      '[CHART] Advanced visualizations (coming soon)\\n' +
                      '[REFRESH] WebSocket live updates (coming soon)');
            }

            // Allow Enter key to trigger search
            document.getElementById('search-input').addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    performSearch();
                }
            });
        </script>
    </body>
    </html>
    """


@app.get("/api/v2/health")
async def health_check():
    """Health check with mode status"""
    return {
        "status": "healthy",
        "timestamp": asyncio.get_event_loop().time(),
        "modes": {
            "futuristic_available": True,
            "legacy_available": legacy_pipeline is not None,
            "agents_active": 0,  # Simplified demo
        },
        "uptime_seconds": asyncio.get_event_loop().time() - (startup_time or 0),
        "message": "Futuristic interface demo with legacy fallback",
    }


@app.post("/api/v2/search", response_model=SearchResponse)
async def futuristic_search(
    request: SearchRequest, background_tasks: BackgroundTasks
):
    """Futuristic search with legacy processing"""

    job_id = str(uuid.uuid4())

    try:
        # Use legacy pipeline for actual processing
        if legacy_pipeline:
            import time

            start_time = time.time()

            # Process query through legacy pipeline
            result = await legacy_pipeline.process_query(request.query)

            processing_time = time.time() - start_time

            # Convert results to response format
            results = []
            if result and result.metadata:
                for item in result.metadata[: request.max_results]:
                    results.append(
                        {
                            "id": item.get("accession", "unknown"),
                            "title": item.get("title", "Unknown Title"),
                            "summary": item.get("summary", "")[:200] + "..."
                            if item.get("summary", "")
                            else "",
                            "source": "GEO Database",
                        }
                    )

            return SearchResponse(
                job_id=job_id,
                status="completed",
                query=request.query,
                results=results,
                total_results=len(results),
                processing_time=processing_time,
                message=f"Found {len(results)} results using futuristic interface with legacy processing",
                mode="futuristic-with-legacy-backend",
            )
        else:
            # No backend available
            return SearchResponse(
                job_id=job_id,
                status="completed",
                query=request.query,
                results=[],
                total_results=0,
                message="Demo mode - no backend processing available",
                mode="demo-only",
            )

    except Exception as e:
        logger.error(f"Search failed: {e}")
        raise HTTPException(
            status_code=500, detail=f"Search processing failed: {str(e)}"
        )


if __name__ == "__main__":
    uvicorn.run(
        "futuristic_demo:app",
        host="0.0.0.0",
        port=8001,
        reload=True,
        log_level="info",
    )
