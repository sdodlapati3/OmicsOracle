"""
V1 API routes for backward compatibility.
"""

from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
async def health_check_v1():
    """V1 health check endpoint."""
    return {"status": "healthy", "version": "1.0", "api": "v1"}
