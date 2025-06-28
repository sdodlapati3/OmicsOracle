"""
Basic health check routes.
"""

from fastapi import APIRouter

from ..dependencies import health_check

router = APIRouter()


@router.get("/")
async def basic_health():
    """Basic health check endpoint."""
    return await health_check()


@router.get("/status")
async def health_status():
    """Health status endpoint."""
    return await health_check()
