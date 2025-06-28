"""
Unified FastAPI application for OmicsOracle.

This module creates the main FastAPI application providing a modern API interface
with comprehensive middleware and routing.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ...core.config import Config
from .dependencies import setup_dependencies
from .middleware import setup_middleware
from .routes import setup_routes
from .websockets import setup_websockets

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context manager."""
    # Startup
    logger.info("Starting OmicsOracle application...")
    logger.info("Application startup complete")

    yield

    # Shutdown
    logger.info("Shutting down OmicsOracle application...")
    logger.info("Application shutdown complete")

    logger.info("Application shutdown complete")


def create_app() -> FastAPI:
    """
    Factory function to create the FastAPI application.

    Returns:
        FastAPI: Configured application instance
    """
    config = Config()

    # Create FastAPI application
    app = FastAPI(
        title="OmicsOracle API",
        description="Advanced biomedical research platform with AI-powered analysis",
        version="3.0.0",
        debug=config.debug,
        lifespan=lifespan,
        docs_url="/docs",  # Always enable docs for development/testing
        redoc_url="/redoc",  # Always enable redoc for development/testing
    )

    # Setup CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://localhost:3001"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

    # Setup custom middleware
    setup_middleware(app, config)

    # Setup dependency injection
    setup_dependencies(app)

    # Setup routes
    setup_routes(app)

    # Setup WebSocket endpoints
    setup_websockets(app)

    logger.info("FastAPI application created successfully")
    return app


# Create the main application instance
app = create_app()


if __name__ == "__main__":
    import uvicorn

    config = Config()
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=config.debug,
        log_level="info",
    )
