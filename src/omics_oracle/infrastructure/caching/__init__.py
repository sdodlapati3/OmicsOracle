"""
Caching infrastructure for the OmicsOracle application.

This module provides caching implementations for improved performance
while ensuring fresh data when needed.
"""

from .cache_decorator import cached
from .memory_cache import MemoryCache

__all__ = ["MemoryCache", "cached"]
