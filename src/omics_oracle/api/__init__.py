"""
FastAPI application for OmicsOracle.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from omics_oracle.config import settings
from omics_oracle.core.exceptions import OmicsOracleException

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
async def root():
    """Root endpoint."""
    return {
        "message": "Welcome to OmicsOracle API",
        "version": "0.1.0",
        "docs": "/docs",
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "environment": settings.environment,
        "version": "0.1.0",
    }


@app.get("/status")
async def system_status():
    """System status endpoint."""
    try:
        # TODO: Add actual status checks for databases, services, etc.
        return {
            "api": "running",
            "database": "connected",
            "cache": "available",
            "ai_service": "available",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"System check failed: {e}")


# TODO: Add more API endpoints for:
# - GEO data processing
# - File upload and analysis
# - AI summarization
# - User management
# - Dataset search and retrieval
