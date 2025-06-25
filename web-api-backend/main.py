"""
FastAPI main application for OmicsOracle web interface.

This module sets up the FastAPI application with all routes and middleware.
"""

import logging
import sys
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

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

# Rate limiting storage
request_counts = defaultdict(list)
RATE_LIMIT = 100  # requests per minute
RATE_LIMIT_WINDOW = 60  # seconds


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware to add security headers to all responses."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers[
            "Strict-Transport-Security"
        ] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' data:; "
            "connect-src 'self' ws: wss:;"
        )
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers[
            "Permissions-Policy"
        ] = "geolocation=(), microphone=(), camera=()"

        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple rate limiting middleware."""

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host
        current_time = time.time()

        # Clean old requests
        request_counts[client_ip] = [
            req_time
            for req_time in request_counts[client_ip]
            if current_time - req_time < RATE_LIMIT_WINDOW
        ]

        # Check rate limit
        if len(request_counts[client_ip]) >= RATE_LIMIT:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded",
                    "message": "Too many requests",
                },
            )

        # Add current request
        request_counts[client_ip].append(current_time)

        response = await call_next(request)
        return response


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

# Add security and rate limiting middleware
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)


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


@app.get("/search")
async def search_page():
    """Search page - serve the web interface."""
    from fastapi.responses import FileResponse

    static_dir = Path(__file__).parent / "static"
    index_file = static_dir / "index.html"

    if index_file.exists():
        return FileResponse(str(index_file))
    else:
        return {
            "message": "OmicsOracle Search Interface",
            "version": "1.0.0",
            "docs": "/api/docs",
            "status": "healthy",
        }


@app.get("/about")
async def about_page():
    """About page - serve basic info."""
    return {
        "message": "OmicsOracle - Biomedical Research Intelligence Platform",
        "version": "1.0.0",
        "description": "AI-powered analysis of genomics datasets from NCBI GEO",
        "features": [
            "Advanced dataset search",
            "AI-powered summarization",
            "Interactive visualizations",
            "Citation management",
            "Research workflow integration",
        ],
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


from .ai_routes import ai_router  # noqa: E402
from .batch_routes import batch_router  # noqa: E402
from .refinement_routes import refinement_router  # noqa: E402

# Import and include routers
from .routes import (  # noqa: E402
    analysis_router,
    config_router,
    dataset_router,
    search_router,
    status_router,
    websocket_router,
)

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
app.include_router(refinement_router, tags=["refinement"])

# Add optional routers if available
if CACHE_AVAILABLE:
    app.include_router(cache_router, prefix="/api", tags=["cache"])

if EXPORT_AVAILABLE:
    app.include_router(export_router, prefix="/api", tags=["export"])

if VISUALIZATION_AVAILABLE:
    app.include_router(
        visualization_router,
        prefix="/api/visualization",
        tags=["visualization"],
    )

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
