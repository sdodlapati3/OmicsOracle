"""
V2 API routes - simplified version.
"""

from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
async def health_check_v2():
    """V2 health check endpoint."""
    return {"status": "healthy", "version": "2.0", "api": "v2"}
