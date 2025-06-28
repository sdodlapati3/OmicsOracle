"""
FastAPI routes setup.

This module configures all API routes for the application including
versioned APIs and legacy compatibility routes.
"""

import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse

from .analysis import router as analysis_router
from .enhanced_search import router as enhanced_search_router
from .health import router as health_router
from .search import router as search_router
from .v1 import router as v1_router
from .v2 import router as v2_router

logger = logging.getLogger(__name__)


def setup_routes(app: FastAPI) -> None:
    """Setup all application routes including versioned APIs."""

    # Health check routes (unversioned for compatibility)
    app.include_router(health_router, prefix="/health", tags=["health"])

    # Enhanced search routes
    app.include_router(enhanced_search_router, prefix="/api/v2", tags=["enhanced-search"])

    # Legacy v1 routes (backward compatibility)
    app.include_router(search_router, prefix="/api/v1/search", tags=["search", "legacy"])

    # Analysis routes
    app.include_router(analysis_router, prefix="/api/v1/analysis", tags=["analysis", "legacy"])

    # Versioned API routes
    app.include_router(v1_router, prefix="/api", tags=["v1", "compatibility"])

    app.include_router(v2_router, prefix="/api", tags=["v2", "advanced"])

    # Default route to serve the web interface
    @app.get("/", tags=["root"])
    async def root():
        """Serve the main web interface."""
        static_dir = Path(__file__).parent.parent / "static"
        index_path = static_dir / "index.html"

        if index_path.exists():
            return FileResponse(str(index_path))
        else:
            return {"error": "Web interface not found"}

    @app.get("/api", tags=["version-discovery"])
    async def api_version_discovery():
        """Discover available API versions."""
        return {
            "api_name": "OmicsOracle API",
            "available_versions": {
                "v1": {
                    "version": "1.0.0",
                    "status": "stable",
                    "endpoints": "/api/v1/",
                    "documentation": "/docs#tag/v1-legacy",
                },
                "v2": {
                    "version": "2.0.0",
                    "status": "active",
                    "endpoints": "/api/v2/",
                    "documentation": "/docs#tag/v2-advanced",
                    "features": [
                        "real-time",
                        "advanced-caching",
                        "microservices",
                    ],
                },
            },
            "recommended_version": "v2",
            "deprecation_notice": "v1 will be deprecated in 6 months",
        }

    logger.info("All routes configured successfully (including v1 & v2 APIs)")
