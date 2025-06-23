"""
Web interface module for OmicsOracle.

This module provides a FastAPI-based web interface for the OmicsOracle pipeline,
offering REST API endpoints and WebSocket support for real-time updates.
"""

from .main import app

__all__ = ["app"]
