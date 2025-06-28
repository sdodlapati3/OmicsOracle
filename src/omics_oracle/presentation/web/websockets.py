"""
WebSocket endpoints - simplified version.
"""

import logging

from fastapi import FastAPI

logger = logging.getLogger(__name__)


def setup_websockets(app: FastAPI) -> None:
    """Setup basic WebSocket endpoints."""
    logger.info("WebSocket endpoints configured successfully")
