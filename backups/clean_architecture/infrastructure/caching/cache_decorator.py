"""
Cache decorator for easy caching of function results.

Provides decorators to easily add caching to functions and methods.
"""

import functools
import hashlib
import json
import logging
from typing import Any, Callable, Optional

from .memory_cache import MemoryCache

logger = logging.getLogger(__name__)

# Global cache instance
_default_cache = MemoryCache()


def cached(
    ttl: Optional[int] = None,
    key_prefix: str = "",
    cache_instance: Optional[MemoryCache] = None,
) -> Callable:
    """
    Decorator to cache function results.

    Args:
        ttl: Time-to-live in seconds (uses cache default if None)
        key_prefix: Prefix for cache keys
        cache_instance: Cache instance to use (uses default if None)
    """

    def decorator(func: Callable) -> Callable:
        cache = cache_instance or _default_cache

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs) -> Any:
            # Generate cache key for debugging purposes
            cache_key = _generate_cache_key(func, args, kwargs, key_prefix)

            # CACHE DISABLED: Always call function for fresh results
            logger.debug(f"Cache disabled for {func.__name__} - calling function directly")

            # Call the function directly (no cache lookup)
            result = await func(*args, **kwargs)

            # Log for debugging/analysis (still store but don't serve from cache)
            logger.debug(f"Generated fresh result for {cache_key}")
            # Note: We could still store for debugging but shouldn't serve from it
            # await cache.set(cache_key, result, ttl)

            return result

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs) -> Any:
            # For sync functions, we can't use async cache easily
            # This is a simplified version
            logger.warning(f"Sync caching not fully implemented for {func.__name__}")
            return func(*args, **kwargs)

        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator


def _generate_cache_key(func: Callable, args: tuple, kwargs: dict, prefix: str = "") -> str:
    """Generate a cache key for function call."""
    # Create a hashable representation
    key_data = {
        "module": func.__module__,
        "function": func.__name__,
        "args": _serialize_args(args),
        "kwargs": _serialize_args(kwargs),
    }

    # Convert to JSON and hash
    key_json = json.dumps(key_data, sort_keys=True, default=str)
    key_hash = hashlib.sha256(key_json.encode()).hexdigest()[:16]

    return f"{prefix}:{func.__name__}:{key_hash}" if prefix else f"{func.__name__}:{key_hash}"


def _serialize_args(obj: Any) -> Any:
    """Serialize arguments for cache key generation."""
    if isinstance(obj, (str, int, float, bool, type(None))):
        return obj
    elif isinstance(obj, (list, tuple)):
        return [_serialize_args(item) for item in obj]
    elif isinstance(obj, dict):
        return {str(k): _serialize_args(v) for k, v in obj.items()}
    else:
        # For complex objects, use string representation
        return str(obj)


# Import asyncio at the end to avoid circular imports
import asyncio
