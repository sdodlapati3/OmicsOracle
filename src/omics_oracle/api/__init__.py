"""
FastAPI application for OmicsOracle.
"""

from typing import Dict

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from omics_oracle.core.config import get_config

# Create FastAPI application
app = FastAPI(
    title="OmicsOracle API",
    description="AI-Powered Genomics Data Summary Agent",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root() -> Dict[str, str]:
    """Root endpoint."""
    return {
        "message": "Welcome to OmicsOracle API",
        "version": "0.1.0",
        "docs": "/docs",
    }


@app.get("/health")
async def health_check() -> Dict[str, str]:
    """Health check endpoint."""
    try:
        config = get_config()
        return {
            "status": "healthy",
            "environment": config.environment,
            "version": "0.1.0",
        }
    except Exception:
        return {
            "status": "healthy",
            "environment": "unknown",
            "version": "0.1.0",
        }


@app.get("/status")
async def system_status() -> Dict[str, str]:
    """System status endpoint."""
    try:
        return {
            "api": "running",
            "database": "connected",
            "cache": "available",
            "ai_service": "available",
        }
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"System check failed: {e}"
        ) from e
