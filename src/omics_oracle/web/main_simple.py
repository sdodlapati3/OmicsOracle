"""
Simplified FastAPI main application for OmicsOracle web interface.

This is a simplified version to get the basic web interface running.
"""

import logging
import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

# Add parent directories to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from omics_oracle.core.config import Config  # noqa: E402

logger = logging.getLogger(__name__)

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


@app.get("/")
async def root():
    """Root endpoint - serve the web interface."""
    static_dir = Path(__file__).parent / "static"
    index_file = static_dir / "index.html"

    if index_file.exists():
        return FileResponse(str(index_file))
    else:
        return {
            "message": "OmicsOracle Web API",
            "version": "1.0.0",
            "docs": "/api/docs",
            "status": "healthy",
        }


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


@app.post("/api/search")
async def search_datasets(request: dict):
    """Basic search endpoint for demonstration."""
    try:
        if not pipeline:
            return JSONResponse(
                status_code=503, content={"error": "Pipeline not initialized"}
            )

        query = request.get("query", "")

        # For now, return a demo response
        return {
            "query_id": "demo_001",
            "original_query": query,
            "status": "completed",
            "processing_time": 0.5,
            "entities": [
                {"text": "cancer", "label": "DISEASE"},
                {"text": "gene expression", "label": "TECHNIQUE"},
            ],
            "metadata": [
                {
                    "id": "GSE123456",
                    "title": f"Demo dataset for: {query}",
                    "summary": "This is a demonstration dataset result.",
                    "organism": "Homo sapiens",
                    "platform": "GPL570",
                    "sample_count": 100,
                }
            ],
        }

    except Exception as e:
        logger.error(f"Search error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})


# Serve static files
static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


if __name__ == "__main__":
    import uvicorn

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Run the application
    uvicorn.run(
        "main:app", host="0.0.0.0", port=8000, reload=True, log_level="info"
    )
