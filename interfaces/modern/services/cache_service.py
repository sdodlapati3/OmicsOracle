"""
Cache service for OmicsOracle modern interface
Handles caching of search results and other data
"""

import hashlib
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Optional

from core.exceptions import CacheException
from core.logging_config import get_service_logger


class CacheService:
    """Service for handling cache operations"""

    def __init__(self, cache_dir: Path, ttl: int = 3600, enabled: bool = True):
        """
        Initialize cache service

        Args:
            cache_dir: Directory for cache files
            ttl: Time to live in seconds (default 1 hour)
            enabled: Whether caching is enabled
        """
        self.cache_dir = cache_dir
        self.ttl = ttl
        self.enabled = enabled
        self.logger = get_service_logger()

        if self.enabled:
            self.cache_dir.mkdir(exist_ok=True)
            self.logger.info(
                f"Cache service initialized: {self.cache_dir} (TTL: {self.ttl}s)"
            )

    def get(self, key: str) -> Optional[Any]:
        """
        Get cached value by key

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found/expired
        """
        if not self.enabled:
            return None

        try:
            cache_file = self._get_cache_file(key)

            if not cache_file.exists():
                return None

            # Check if cache entry is expired
            file_age = time.time() - cache_file.stat().st_mtime
            if file_age > self.ttl:
                self.logger.debug(f"Cache entry expired: {key}")
                cache_file.unlink(missing_ok=True)
                return None

            # Read and deserialize cache entry
            with open(cache_file, "r", encoding="utf-8") as f:
                cache_data = json.load(f)

            self.logger.debug(f"Cache hit: {key}")
            return cache_data.get("value")

        except Exception as e:
            self.logger.warning(f"Cache read failed for key '{key}': {str(e)}")
            return None

    def set(self, key: str, value: Any) -> bool:
        """
        Set cache value for key

        Args:
            key: Cache key
            value: Value to cache

        Returns:
            True if successful, False otherwise
        """
        if not self.enabled:
            return True

        try:
            cache_file = self._get_cache_file(key)

            cache_data = {
                "key": key,
                "value": value,
                "created_at": datetime.now().isoformat(),
                "ttl": self.ttl,
            }

            # Write cache entry
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(cache_data, f, indent=2, default=str)

            self.logger.debug(f"Cache set: {key}")
            return True

        except Exception as e:
            self.logger.warning(f"Cache write failed for key '{key}': {str(e)}")
            return False

    def delete(self, key: str) -> bool:
        """
        Delete cache entry

        Args:
            key: Cache key to delete

        Returns:
            True if successful, False otherwise
        """
        if not self.enabled:
            return True

        try:
            cache_file = self._get_cache_file(key)
            cache_file.unlink(missing_ok=True)
            self.logger.debug(f"Cache deleted: {key}")
            return True

        except Exception as e:
            self.logger.warning(
                f"Cache delete failed for key '{key}': {str(e)}"
            )
            return False

    def clear(self) -> bool:
        """
        Clear all cache entries

        Returns:
            True if successful, False otherwise
        """
        if not self.enabled:
            return True

        try:
            for cache_file in self.cache_dir.glob("*.json"):
                cache_file.unlink(missing_ok=True)

            self.logger.info("Cache cleared")
            return True

        except Exception as e:
            self.logger.error(f"Cache clear failed: {str(e)}")
            return False

    def cleanup_expired(self) -> int:
        """
        Clean up expired cache entries

        Returns:
            Number of entries cleaned up
        """
        if not self.enabled:
            return 0

        cleaned_count = 0

        try:
            current_time = time.time()

            for cache_file in self.cache_dir.glob("*.json"):
                try:
                    file_age = current_time - cache_file.stat().st_mtime
                    if file_age > self.ttl:
                        cache_file.unlink(missing_ok=True)
                        cleaned_count += 1
                except Exception as e:
                    self.logger.warning(
                        f"Failed to check cache file {cache_file}: {str(e)}"
                    )

            if cleaned_count > 0:
                self.logger.info(
                    f"Cleaned up {cleaned_count} expired cache entries"
                )

            return cleaned_count

        except Exception as e:
            self.logger.error(f"Cache cleanup failed: {str(e)}")
            return 0

    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics

        Returns:
            Dictionary with cache statistics
        """
        stats = {
            "enabled": self.enabled,
            "cache_dir": str(self.cache_dir),
            "ttl": self.ttl,
            "total_entries": 0,
            "total_size_bytes": 0,
            "oldest_entry": None,
            "newest_entry": None,
        }

        if not self.enabled:
            return stats

        try:
            cache_files = list(self.cache_dir.glob("*.json"))
            stats["total_entries"] = len(cache_files)

            if cache_files:
                total_size = sum(f.stat().st_size for f in cache_files)
                stats["total_size_bytes"] = total_size

                # Find oldest and newest entries
                oldest_file = min(cache_files, key=lambda f: f.stat().st_mtime)
                newest_file = max(cache_files, key=lambda f: f.stat().st_mtime)

                stats["oldest_entry"] = datetime.fromtimestamp(
                    oldest_file.stat().st_mtime
                ).isoformat()
                stats["newest_entry"] = datetime.fromtimestamp(
                    newest_file.stat().st_mtime
                ).isoformat()

        except Exception as e:
            self.logger.warning(f"Failed to get cache stats: {str(e)}")

        return stats

    def _get_cache_file(self, key: str) -> Path:
        """Get cache file path for key"""
        # Create a safe filename from the key
        key_hash = hashlib.md5(key.encode("utf-8")).hexdigest()
        return self.cache_dir / f"cache_{key_hash}.json"

    def cache_search_result(
        self, query: str, page: int, page_size: int, result: Any
    ) -> bool:
        """Cache search result with structured key"""
        cache_key = f"search:{hashlib.md5(query.encode()).hexdigest()}:{page}:{page_size}"
        return self.set(cache_key, result)

    def get_cached_search_result(
        self, query: str, page: int, page_size: int
    ) -> Optional[Any]:
        """Get cached search result with structured key"""
        cache_key = f"search:{hashlib.md5(query.encode()).hexdigest()}:{page}:{page_size}"
        return self.get(cache_key)
