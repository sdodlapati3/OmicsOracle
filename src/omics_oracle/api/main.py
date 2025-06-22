"""
Main FastAPI application entry point.
"""

from omics_oracle.api import app

# This allows uvicorn to find the app instance
# Usage: uvicorn omics_oracle.api.main:app
__all__ = ["app"]
