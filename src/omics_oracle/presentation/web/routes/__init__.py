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
from .futuristic_search import router as futuristic_search_router
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

    # Futuristic search routes
    app.include_router(futuristic_search_router, prefix="/api", tags=["futuristic", "search"])

    # Default route to serve the web interface
    @app.get("/", tags=["root"])
    async def root():
        """Serve the main web interface."""
        static_dir = Path(__file__).parent.parent / "static"
        # Use the enhanced futuristic interface as the default (restored from backup)
        enhanced_path = static_dir / "futuristic_enhanced.html"

        if enhanced_path.exists():
            return FileResponse(str(enhanced_path))
        else:
            # Fallback to research intelligence dashboard
            dashboard_path = static_dir / "research_intelligence_dashboard.html"
            if dashboard_path.exists():
                return FileResponse(str(dashboard_path))
            else:
                # Final fallback to basic index
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

    # Additional dashboard routes
    @app.get("/dashboard/basic", tags=["dashboard"])
    async def basic_dashboard():
        """Serve the basic dashboard interface."""
        static_dir = Path(__file__).parent.parent / "static"
        index_path = static_dir / "index.html"
        if index_path.exists():
            return FileResponse(str(index_path))
        else:
            return {"error": "Basic dashboard not found"}

    @app.get("/dashboard/research", tags=["dashboard"])
    async def research_dashboard():
        """Serve the research dashboard interface."""
        static_dir = Path(__file__).parent.parent / "static"
        dashboard_path = static_dir / "research_dashboard.html"
        if dashboard_path.exists():
            return FileResponse(str(dashboard_path))
        else:
            return {"error": "Research dashboard not found"}

    @app.get("/dashboard/intelligence", tags=["dashboard"])
    async def intelligence_dashboard():
        """Serve the research intelligence dashboard interface."""
        static_dir = Path(__file__).parent.parent / "static"
        dashboard_path = static_dir / "research_intelligence_dashboard.html"
        if dashboard_path.exists():
            return FileResponse(str(dashboard_path))
        else:
            return {"error": "Research intelligence dashboard not found"}

    @app.get("/dashboard/advanced", tags=["dashboard"])
    async def advanced_dashboard():
        """Serve the most advanced dashboard interface."""
        static_dir = Path(__file__).parent.parent / "static"
        dashboard_path = static_dir / "dashboard.html"
        if dashboard_path.exists():
            return FileResponse(str(dashboard_path))
        else:
            return {"error": "Advanced dashboard not found"}

    @app.get("/dashboards", tags=["dashboard"])
    async def list_dashboards():
        """List all available dashboard interfaces."""
        static_dir = Path(__file__).parent.parent / "static"
        dashboards = []

        dashboard_files = {
            "basic": "index.html",
            "research": "research_dashboard.html",
            "intelligence": "research_intelligence_dashboard.html",
            "advanced": "dashboard.html",
            "futuristic": "futuristic_interface.html",
            "futuristic-enhanced": "futuristic_enhanced.html",
        }

        for name, filename in dashboard_files.items():
            file_path = static_dir / filename
            if file_path.exists():
                if name == "futuristic":
                    url = "/futuristic"
                elif name == "futuristic-enhanced":
                    url = "/futuristic-enhanced"
                else:
                    url = f"/dashboard/{name}"
                dashboards.append(
                    {
                        "name": name,
                        "url": url,
                        "description": f"{name.title()} dashboard interface",
                    }
                )

        return {"available_dashboards": dashboards, "default": "/", "current_default": "intelligence"}

    # Futuristic interface route
    @app.get("/futuristic", tags=["dashboard"])
    async def futuristic_interface():
        """Serve the futuristic next-generation interface."""
        static_dir = Path(__file__).parent.parent / "static"
        futuristic_path = static_dir / "futuristic_interface.html"
        if futuristic_path.exists():
            return FileResponse(str(futuristic_path))
        else:
            return {"error": "Futuristic interface not found"}

    # Enhanced futuristic interface route (restored from backup)
    @app.get("/futuristic-enhanced", tags=["dashboard"])
    async def futuristic_enhanced_interface():
        """Serve the enhanced futuristic interface with agent monitoring."""
        return FileResponse("src/omics_oracle/presentation/web/static/futuristic_enhanced.html")

    # Enhanced futuristic interface route (additional)
    @app.get("/enhanced", tags=["dashboard"])
    async def enhanced_interface():
        """Serve the enhanced futuristic interface"""
        static_dir = Path(__file__).parent.parent / "static"
        enhanced_path = static_dir / "futuristic_enhanced.html"
        if enhanced_path.exists():
            return FileResponse(str(enhanced_path))
        else:
            return {"error": "Enhanced futuristic interface not found"}

    logger.info("All routes configured successfully (including v1 & v2 APIs)")
