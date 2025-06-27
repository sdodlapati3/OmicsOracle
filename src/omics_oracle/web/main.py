"""
FastAPI main application for OmicsOracle web interface.

This module sets up the FastAPI application with all routes and middleware.
"""

import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

# Add parent directories to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from omics_oracle.core.config import Config  # noqa: E402
from omics_oracle.pipeline import OmicsOracle  # noqa: E402
from omics_oracle.web.models import ErrorResponse  # noqa: E402

logger = logging.getLogger(__name__)

# Global variables for application state
pipeline: OmicsOracle = None
config: Config = None
active_queries: Dict[str, Any] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global pipeline, config

    # Startup
    logger.info("Starting OmicsOracle Web API...")
    try:
        config = Config()
        pipeline = OmicsOracle(config)
        logger.info("Pipeline initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize pipeline: {e}")
        raise

    yield

    # Shutdown
    logger.info("Shutting down OmicsOracle Web API...")
    # Cleanup active queries
    active_queries.clear()


# Create FastAPI application
app = FastAPI(
    title="OmicsOracle Web API",
    description="REST API for OmicsOracle GEO dataset search and analysis",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
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


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Custom HTTP exception handler."""
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error="HTTP_ERROR",
            message=exc.detail,
            details={"status_code": exc.status_code},
        ).dict(),
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """General exception handler."""
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="INTERNAL_ERROR",
            message="An internal server error occurred",
            details={"exception": str(exc)},
        ).dict(),
    )


@app.get("/")
async def root():
    """Root endpoint - serve the web interface."""
    from fastapi.responses import FileResponse

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
        "active_queries": len(active_queries),
    }


# Import and include routers
from .routes import (  # noqa: E402
    analysis_router,
    config_router,
    dataset_router,
    search_router,
    status_router,
    websocket_router,
)
from .ai_routes import ai_router  # noqa: E402
from .batch_routes import batch_router  # noqa: E402

try:
    from .visualization_routes import visualization_router  # noqa: E402
    VISUALIZATION_AVAILABLE = True
except ImportError:
    VISUALIZATION_AVAILABLE = False

try:
    from .cache_routes import cache_router  # noqa: E402
    CACHE_AVAILABLE = True
except ImportError:
    CACHE_AVAILABLE = False

try:
    from .export_routes import export_router  # noqa: E402
    EXPORT_AVAILABLE = True
except ImportError:
    EXPORT_AVAILABLE = False

try:
    from .research_dashboard import router as research_router  # noqa: E402
    RESEARCH_DASHBOARD_AVAILABLE = True
except ImportError:
    RESEARCH_DASHBOARD_AVAILABLE = False

try:
    from .advanced_widgets import advanced_router  # noqa: E402
    ADVANCED_WIDGETS_AVAILABLE = True
except ImportError:
    ADVANCED_WIDGETS_AVAILABLE = False

try:
    from .research_query_engine import query_router  # noqa: E402
    RESEARCH_QUERY_AVAILABLE = True
except ImportError:
    RESEARCH_QUERY_AVAILABLE = False

app.include_router(search_router, prefix="/api", tags=["search"])
app.include_router(dataset_router, prefix="/api", tags=["datasets"])
app.include_router(analysis_router, prefix="/api", tags=["analysis"])
app.include_router(config_router, prefix="/api", tags=["config"])
app.include_router(status_router, prefix="/api", tags=["status"])
app.include_router(websocket_router, prefix="/api", tags=["websocket"])
app.include_router(ai_router, prefix="/api", tags=["ai"])
app.include_router(batch_router, prefix="/api", tags=["batch-processing"])

# Add optional routers if available
if CACHE_AVAILABLE:
    app.include_router(cache_router, prefix="/api", tags=["cache"])
    
if EXPORT_AVAILABLE:
    app.include_router(export_router, prefix="/api", tags=["export"])

if VISUALIZATION_AVAILABLE:
    app.include_router(visualization_router, prefix="/api/visualization", tags=["visualization"])

if RESEARCH_DASHBOARD_AVAILABLE:
    app.include_router(research_router, prefix="", tags=["research-dashboard"])

if ADVANCED_WIDGETS_AVAILABLE:
    app.include_router(advanced_router, prefix="", tags=["advanced-widgets"])

if RESEARCH_QUERY_AVAILABLE:
    app.include_router(query_router, prefix="", tags=["research-queries"])


# Serve static files (for frontend)
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
        "omics_oracle.web.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
