"""
Memory-based caching implementation.

Provides a simple in-memory cache with TTL support for development
and testing. In production, this should be replaced with Redis or
similar distributed cache.
"""

import asyncio
import logging
import time
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


class MemoryCache:
    """Simple in-memory cache with TTL support."""

    def __init__(self, default_ttl: int = 300):
        """
        Initialize the memory cache.

        Args:
            default_ttl: Default time-to-live in seconds
        """
        self._cache: Dict[str, Tuple[Any, float]] = {}
        self._default_ttl = default_ttl
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Any]:
        """Get a value from cache."""
        async with self._lock:
            if key not in self._cache:
                return None

            value, expires_at = self._cache[key]

            # Check if expired
            if time.time() > expires_at:
                del self._cache[key]
                logger.debug(f"Cache key expired: {key}")
                return None

            logger.debug(f"Cache hit: {key}")
            return value

    async def set(
        self, key: str, value: Any, ttl: Optional[int] = None
    ) -> None:
        """Set a value in cache."""
        if ttl is None:
            ttl = self._default_ttl

        expires_at = time.time() + ttl

        async with self._lock:
            self._cache[key] = (value, expires_at)
            logger.debug(f"Cache set: {key} (TTL: {ttl}s)")

    async def delete(self, key: str) -> bool:
        """Delete a key from cache."""
        async with self._lock:
            if key in self._cache:
                del self._cache[key]
                logger.debug(f"Cache deleted: {key}")
                return True
            return False

    async def clear(self) -> None:
        """Clear all cache entries."""
        async with self._lock:
            self._cache.clear()
            logger.debug("Cache cleared")

    async def cleanup_expired(self) -> int:
        """Remove expired entries and return count of removed items."""
        current_time = time.time()
        expired_keys = []

        async with self._lock:
            for key, (_, expires_at) in self._cache.items():
                if current_time > expires_at:
                    expired_keys.append(key)

            for key in expired_keys:
                del self._cache[key]

        if expired_keys:
            logger.debug(
                f"Cleaned up {len(expired_keys)} expired cache entries"
            )

        return len(expired_keys)

    def size(self) -> int:
        """Get the current cache size."""
        return len(self._cache)

    async def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        current_time = time.time()
        expired_count = 0

        async with self._lock:
            for _, expires_at in self._cache.values():
                if current_time > expires_at:
                    expired_count += 1

        return {
            "total_keys": len(self._cache),
            "expired_keys": expired_count,
            "active_keys": len(self._cache) - expired_count,
            "default_ttl": self._default_ttl,
        }
