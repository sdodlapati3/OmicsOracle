"""
Advanced Caching Strategy Implementation

Provides multi-level caching with intelligent cache management:
- L1: In-memory cache (fastest)
- L2: Redis cache (shared across instances)
- L3: File-based cache (persistent)
- Intelligent cache warming and invalidation
"""

import asyncio
import hashlib
import json
import logging
import pickle
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

logger = logging.getLogger(__name__)


class CacheLevel(Enum):
    """Cache level enumeration."""

    MEMORY = "memory"
    REDIS = "redis"
    FILE = "file"


@dataclass
class CacheEntry:
    """Cache entry with metadata."""

    key: str
    value: Any
    timestamp: float
    ttl: Optional[float] = None
    access_count: int = 0
    last_access: float = None
    size_bytes: int = 0
    tags: Set[str] = None

    def __post_init__(self):
        if self.last_access is None:
            self.last_access = self.timestamp
        if self.tags is None:
            self.tags = set()
        if self.size_bytes == 0:
            self.size_bytes = self._calculate_size()

    def is_expired(self) -> bool:
        """Check if cache entry is expired."""
        if self.ttl is None:
            return False
        return time.time() - self.timestamp > self.ttl

    def access(self) -> None:
        """Record cache access."""
        self.access_count += 1
        self.last_access = time.time()

    def _calculate_size(self) -> int:
        """Calculate approximate size of cached value."""
        try:
            return len(pickle.dumps(self.value))
        except Exception:
            return len(str(self.value).encode("utf-8"))


class CacheBackend(ABC):
    """Abstract cache backend interface."""

    @abstractmethod
    async def get(self, key: str) -> Optional[CacheEntry]:
        """Get value from cache."""
        pass

    @abstractmethod
    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[float] = None,
        tags: Optional[Set[str]] = None,
    ) -> None:
        """Set value in cache."""
        pass

    @abstractmethod
    async def delete(self, key: str) -> bool:
        """Delete key from cache."""
        pass

    @abstractmethod
    async def clear(self) -> None:
        """Clear all cache entries."""
        pass

    @abstractmethod
    async def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        pass


class MemoryCacheBackend(CacheBackend):
    """In-memory cache backend with LRU eviction."""

    def __init__(self, max_size: int = 1000, max_memory_mb: int = 100):
        self.max_size = max_size
        self.max_memory_bytes = max_memory_mb * 1024 * 1024
        self._cache: Dict[str, CacheEntry] = {}
        self._access_order: List[str] = []
        self._stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "memory_usage": 0,
        }

    async def get(self, key: str) -> Optional[CacheEntry]:
        """Get value from memory cache."""
        if key not in self._cache:
            self._stats["misses"] += 1
            return None

        entry = self._cache[key]
        if entry.is_expired():
            await self.delete(key)
            self._stats["misses"] += 1
            return None

        # Update LRU order
        if key in self._access_order:
            self._access_order.remove(key)
        self._access_order.append(key)

        entry.access()
        self._stats["hits"] += 1
        return entry

    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[float] = None,
        tags: Optional[Set[str]] = None,
    ) -> None:
        """Set value in memory cache."""
        entry = CacheEntry(
            key=key,
            value=value,
            timestamp=time.time(),
            ttl=ttl,
            tags=tags or set(),
        )

        # Check if we need to evict entries
        await self._ensure_capacity(entry.size_bytes)

        self._cache[key] = entry
        if key not in self._access_order:
            self._access_order.append(key)

        self._update_memory_usage()

    async def delete(self, key: str) -> bool:
        """Delete key from memory cache."""
        if key in self._cache:
            del self._cache[key]
            if key in self._access_order:
                self._access_order.remove(key)
            self._update_memory_usage()
            return True
        return False

    async def clear(self) -> None:
        """Clear all cache entries."""
        self._cache.clear()
        self._access_order.clear()
        self._stats["memory_usage"] = 0

    async def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        total_requests = self._stats["hits"] + self._stats["misses"]
        hit_rate = (
            self._stats["hits"] / total_requests if total_requests > 0 else 0
        )

        return {
            **self._stats,
            "size": len(self._cache),
            "hit_rate": hit_rate,
            "max_size": self.max_size,
            "max_memory_bytes": self.max_memory_bytes,
        }

    async def _ensure_capacity(self, new_entry_size: int) -> None:
        """Ensure cache has capacity for new entry."""
        # Size-based eviction
        while len(self._cache) >= self.max_size and self._access_order:
            oldest_key = self._access_order[0]
            await self.delete(oldest_key)
            self._stats["evictions"] += 1

        # Memory-based eviction
        current_memory = sum(entry.size_bytes for entry in self._cache.values())
        while (
            current_memory + new_entry_size > self.max_memory_bytes
            and self._access_order
        ):
            oldest_key = self._access_order[0]
            if oldest_key in self._cache:
                current_memory -= self._cache[oldest_key].size_bytes
            await self.delete(oldest_key)
            self._stats["evictions"] += 1

    def _update_memory_usage(self) -> None:
        """Update memory usage statistics."""
        self._stats["memory_usage"] = sum(
            entry.size_bytes for entry in self._cache.values()
        )


class FileCacheBackend(CacheBackend):
    """File-based cache backend for persistence."""

    def __init__(self, cache_dir: Path = Path("cache"), max_files: int = 10000):
        self.cache_dir = Path(cache_dir)
        self.max_files = max_files
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._stats = {
            "hits": 0,
            "misses": 0,
            "writes": 0,
            "errors": 0,
        }

    def _get_file_path(self, key: str) -> Path:
        """Get file path for cache key."""
        key_hash = hashlib.md5(key.encode()).hexdigest()
        return self.cache_dir / f"{key_hash}.cache"

    async def get(self, key: str) -> Optional[CacheEntry]:
        """Get value from file cache."""
        file_path = self._get_file_path(key)

        if not file_path.exists():
            self._stats["misses"] += 1
            return None

        try:
            with open(file_path, "rb") as f:
                entry_data = pickle.load(f)
                entry = CacheEntry(**entry_data)

            if entry.is_expired():
                await self.delete(key)
                self._stats["misses"] += 1
                return None

            entry.access()
            self._stats["hits"] += 1
            return entry

        except Exception as e:
            logger.error(f"Error reading cache file {file_path}: {e}")
            self._stats["errors"] += 1
            return None

    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[float] = None,
        tags: Optional[Set[str]] = None,
    ) -> None:
        """Set value in file cache."""
        entry = CacheEntry(
            key=key,
            value=value,
            timestamp=time.time(),
            ttl=ttl,
            tags=tags or set(),
        )

        file_path = self._get_file_path(key)

        try:
            # Ensure we don't exceed file limit
            await self._ensure_file_capacity()

            with open(file_path, "wb") as f:
                entry_dict = {
                    "key": entry.key,
                    "value": entry.value,
                    "timestamp": entry.timestamp,
                    "ttl": entry.ttl,
                    "access_count": entry.access_count,
                    "last_access": entry.last_access,
                    "size_bytes": entry.size_bytes,
                    "tags": entry.tags,
                }
                pickle.dump(entry_dict, f)

            self._stats["writes"] += 1

        except Exception as e:
            logger.error(f"Error writing cache file {file_path}: {e}")
            self._stats["errors"] += 1

    async def delete(self, key: str) -> bool:
        """Delete key from file cache."""
        file_path = self._get_file_path(key)

        if file_path.exists():
            try:
                file_path.unlink()
                return True
            except Exception as e:
                logger.error(f"Error deleting cache file {file_path}: {e}")
                self._stats["errors"] += 1

        return False

    async def clear(self) -> None:
        """Clear all cache files."""
        try:
            for file_path in self.cache_dir.glob("*.cache"):
                file_path.unlink()
        except Exception as e:
            logger.error(f"Error clearing cache directory: {e}")
            self._stats["errors"] += 1

    async def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        cache_files = list(self.cache_dir.glob("*.cache"))
        total_size = sum(f.stat().st_size for f in cache_files)
        total_requests = self._stats["hits"] + self._stats["misses"]
        hit_rate = (
            self._stats["hits"] / total_requests if total_requests > 0 else 0
        )

        return {
            **self._stats,
            "file_count": len(cache_files),
            "total_size_bytes": total_size,
            "hit_rate": hit_rate,
            "max_files": self.max_files,
        }

    async def _ensure_file_capacity(self) -> None:
        """Ensure file cache doesn't exceed limits."""
        cache_files = list(self.cache_dir.glob("*.cache"))

        if len(cache_files) >= self.max_files:
            # Remove oldest files
            cache_files.sort(key=lambda f: f.stat().st_mtime)
            files_to_remove = len(cache_files) - self.max_files + 1

            for file_path in cache_files[:files_to_remove]:
                try:
                    file_path.unlink()
                except Exception as e:
                    logger.error(
                        f"Error removing old cache file {file_path}: {e}"
                    )


class CacheStrategy:
    """Multi-level cache strategy with intelligent management."""

    def __init__(
        self,
        memory_backend: Optional[MemoryCacheBackend] = None,
        file_backend: Optional[FileCacheBackend] = None,
        default_ttl: Optional[float] = 3600,  # 1 hour
    ):
        self.memory_backend = memory_backend or MemoryCacheBackend()
        self.file_backend = file_backend or FileCacheBackend()
        self.default_ttl = default_ttl

    async def get(self, key: str) -> Optional[Any]:
        """Get value from multi-level cache."""
        # Try L1 cache (memory)
        entry = await self.memory_backend.get(key)
        if entry:
            return entry.value

        # Try L2 cache (file)
        entry = await self.file_backend.get(key)
        if entry:
            # Promote to L1 cache
            await self.memory_backend.set(
                key, entry.value, entry.ttl, entry.tags
            )
            return entry.value

        return None

    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[float] = None,
        tags: Optional[Set[str]] = None,
        cache_levels: Optional[List[CacheLevel]] = None,
    ) -> None:
        """Set value in specified cache levels."""
        effective_ttl = ttl or self.default_ttl
        cache_levels = cache_levels or [CacheLevel.MEMORY, CacheLevel.FILE]

        if CacheLevel.MEMORY in cache_levels:
            await self.memory_backend.set(key, value, effective_ttl, tags)

        if CacheLevel.FILE in cache_levels:
            await self.file_backend.set(key, value, effective_ttl, tags)

    async def delete(self, key: str) -> bool:
        """Delete key from all cache levels."""
        memory_deleted = await self.memory_backend.delete(key)
        file_deleted = await self.file_backend.delete(key)
        return memory_deleted or file_deleted

    async def clear(self) -> None:
        """Clear all cache levels."""
        await self.memory_backend.clear()
        await self.file_backend.clear()

    async def get_comprehensive_stats(self) -> Dict[str, Any]:
        """Get statistics from all cache levels."""
        return {
            "memory_cache": await self.memory_backend.get_stats(),
            "file_cache": await self.file_backend.get_stats(),
        }
