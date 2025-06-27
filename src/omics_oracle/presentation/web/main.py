"""
Unified FastAPI application using Clean Architecture.

This module creates the main FastAPI application that integrates all layers
of the Clean Architecture, providing a modern API interface with dependency
injection, WebSocket support, and comprehensive middleware.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ...infrastructure.configuration.config import get_config
from ...infrastructure.dependencies.container import Container
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

    # Initialize dependency injection container with all registrations
    from ...infrastructure.dependencies.providers import (
        create_container,
        setup_event_subscribers,
    )

    container = await create_container()
    await setup_event_subscribers(container)
    app.state.container = container

    logger.info("Application startup complete")

    yield

    # Shutdown
    logger.info("Shutting down OmicsOracle application...")

    # Cleanup resources
    if hasattr(app.state, "container"):
        await app.state.container.clear()

    logger.info("Application shutdown complete")


def create_app() -> FastAPI:
    """
    Factory function to create the FastAPI application.

    Returns:
        FastAPI: Configured application instance
    """
    config = get_config()

    # Create FastAPI application
    app = FastAPI(
        title="OmicsOracle API",
        description="Advanced biomedical research platform with AI-powered analysis",
        version="3.0.0",
        debug=config.debug,
        lifespan=lifespan,
        docs_url="/docs" if config.debug else None,
        redoc_url="/redoc" if config.debug else None,
    )

    # Setup CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.security.cors_origins or ["http://localhost:3000"],
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

    config = get_config()
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=config.debug,
        log_level=config.logging.level.lower(),
    )
