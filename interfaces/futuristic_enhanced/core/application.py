"""
Core application factory for the enhanced interface
"""

from pathlib import Path

from api.routes import create_api_router
from core.config import EnhancedConfig
from core.health import create_health_router
from core.performance import PerformanceMiddleware
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from ui.routes_clean import (  # Use clean version with static files
    create_ui_router,
)
from websocket.manager import create_websocket_router


def create_app(config: EnhancedConfig) -> FastAPI:
    """Create and configure the FastAPI application"""

    app = FastAPI(
        title=config.title,
        description=config.description,
        version=config.version,
    )

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.cors_origins,
        allow_credentials=config.cors_credentials,
        allow_methods=config.cors_methods,
        allow_headers=config.cors_headers,
    )

    # Add performance monitoring middleware
    app.add_middleware(PerformanceMiddleware)

    # Mount static files
    static_dir = Path(__file__).parent.parent / "static"
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # Include routers
    app.include_router(create_ui_router(), prefix="", tags=["UI"])
    app.include_router(create_api_router(config), prefix="/api", tags=["API"])
    app.include_router(create_health_router(), prefix="/api", tags=["Health"])
    app.include_router(
        create_websocket_router(config), prefix="", tags=["WebSocket"]
    )

    return app
