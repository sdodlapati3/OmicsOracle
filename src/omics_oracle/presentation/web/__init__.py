"""
Web presentation layer for OmicsOracle.

This package contains the FastAPI application with all routes,
middleware, WebSocket endpoints, and dependency injection setup.
"""

from .main import app, create_app

__all__ = ["app", "create_app"]
