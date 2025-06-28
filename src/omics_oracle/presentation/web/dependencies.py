"""
FastAPI dependency injection setup.

This module configures dependency injection for the FastAPI application.
"""

import logging

from fastapi import FastAPI

from ...core.config import Config

logger = logging.getLogger(__name__)


def setup_dependencies(app: FastAPI) -> None:
    """Setup basic dependencies for the FastAPI application."""
    logger.info("FastAPI dependencies configured")


# Basic configuration dependency
def get_config() -> Config:
    """Get application configuration."""
    return Config()


# Health check endpoint
async def health_check() -> dict:
    """Basic health check."""
    return {"status": "healthy", "service": "omics_oracle_backend", "version": "3.0.0"}
