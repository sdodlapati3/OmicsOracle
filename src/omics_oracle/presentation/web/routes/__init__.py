"""
FastAPI routes setup.

This module configures all API routes for the application including
versioned APIs and legacy compatibility routes.
"""

import logging

from fastapi import FastAPI

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

    # Default route for API version discovery
    @app.get("/", tags=["root"])
    async def root():
        """Welcome page for OmicsOracle API."""
        return {
            "message": "Welcome to OmicsOracle - Genomics Data Analysis Platform",
            "description": "Natural language queries for NCBI GEO genomics data with AI-powered summarization",
            "version": "2.0.0",
            "status": "production",
            "api_documentation": "/docs",
            "health_check": "/health",
            "api_discovery": "/api",
            "quick_start": {
                "example_query": "POST /api/v2/query with {'query': 'cancer stem cells'}",
                "enhanced_search": "GET /api/v2/search/enhanced?query=cancer+stem+cells",
                "health_status": "GET /health",
            },
            "capabilities": [
                "Enhanced query processing with biomedical NLP",
                "Semantic search and result ranking",
                "AI-powered data summarization",
                "Real-time search enhancement",
                "Comprehensive genomics data analysis",
            ],
        }

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
