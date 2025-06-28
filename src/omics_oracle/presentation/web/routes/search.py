"""
Search API routes - simplified version.
"""

from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
async def search_health():
    """Search service health check."""
    return {"status": "healthy", "service": "search", "endpoints": ["analysis", "enhanced_search"]}
