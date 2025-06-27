"""
File-based cache implementation for L3 caching
"""

import asyncio
import hashlib
import json
import logging
import os
import pickle
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


class FileCache:
    """
    Simple file-based cache for L3 caching
    """

    def __init__(
        self,
        cache_dir: str = "data/cache",
        default_ttl: int = 86400,  # 24 hours
        max_file_size: int = 10 * 1024 * 1024,  # 10MB
        serialization: str = "pickle",
    ):
        self.cache_dir = Path(cache_dir)
        self.default_ttl = default_ttl
        self.max_file_size = max_file_size
        self.serialization = serialization

        # Create cache directory
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Statistics
        self.stats = {
            "hits": 0,
            "misses": 0,
            "sets": 0,
            "deletes": 0,
            "errors": 0,
        }

        self.logger = logging.getLogger(__name__)

    def _get_file_path(self, key: str) -> Path:
        """Get file path for cache key"""
        # Create a safe filename from the key
        safe_key = hashlib.md5(key.encode()).hexdigest()
        return self.cache_dir / f"{safe_key}.cache"

    def _serialize(self, value: Any) -> bytes:
        """Serialize value for storage"""
        if self.serialization == "json":
            return json.dumps(value, default=str).encode("utf-8")
        else:  # pickle
            return pickle.dumps(value)

    def _deserialize(self, data: bytes) -> Any:
        """Deserialize value from storage"""
        if self.serialization == "json":
            return json.loads(data.decode("utf-8"))
        else:  # pickle
            return pickle.loads(data)

    async def get(self, key: str, default: Any = None) -> Any:
        """Get value from file cache"""
        try:
            file_path = self._get_file_path(key)

            if not file_path.exists():
                self.stats["misses"] += 1
                return default

            # Read metadata and data
            with open(file_path, "rb") as f:
                # Read header (creation time, TTL)
                header = f.read(16)  # 8 bytes for time, 8 for TTL
                if len(header) < 16:
                    self.stats["misses"] += 1
                    return default

                created_at = float.fromhex(header[:8].hex())
                ttl = float.fromhex(header[8:16].hex())

                # Check TTL
                if ttl > 0 and time.time() > (created_at + ttl):
                    # Expired, delete file
                    try:
                        file_path.unlink()
                    except:
                        pass
                    self.stats["misses"] += 1
                    return default

                # Read data
                data = f.read()
                if not data:
                    self.stats["misses"] += 1
                    return default

                # Deserialize
                value = self._deserialize(data)
                self.stats["hits"] += 1
                return value

        except Exception as e:
            self.logger.error(f"File cache get error for key '{key}': {e}")
            self.stats["errors"] += 1
            return default

    async def set(
        self, key: str, value: Any, ttl: Optional[int] = None
    ) -> bool:
        """Set value in file cache"""
        try:
            if ttl is None:
                ttl = self.default_ttl

            # Serialize value
            data = self._serialize(value)

            # Check size limit
            if len(data) > self.max_file_size:
                self.logger.warning(
                    f"Value too large for file cache: {len(data)} bytes"
                )
                return False

            file_path = self._get_file_path(key)

            # Write to temporary file first, then rename (atomic operation)
            temp_path = file_path.with_suffix(".tmp")

            with open(temp_path, "wb") as f:
                # Write header (creation time, TTL)
                created_at = time.time()
                header = bytes.fromhex(f"{created_at:016x}") + bytes.fromhex(
                    f"{ttl:016x}"
                )
                f.write(header)

                # Write data
                f.write(data)

            # Atomic rename
            temp_path.rename(file_path)

            self.stats["sets"] += 1
            return True

        except Exception as e:
            self.logger.error(f"File cache set error for key '{key}': {e}")
            self.stats["errors"] += 1
            return False

    async def delete(self, key: str) -> bool:
        """Delete value from file cache"""
        try:
            file_path = self._get_file_path(key)

            if file_path.exists():
                file_path.unlink()
                self.stats["deletes"] += 1
                return True

            return False

        except Exception as e:
            self.logger.error(f"File cache delete error for key '{key}': {e}")
            self.stats["errors"] += 1
            return False

    async def exists(self, key: str) -> bool:
        """Check if key exists in file cache"""
        try:
            file_path = self._get_file_path(key)

            if not file_path.exists():
                return False

            # Quick TTL check
            with open(file_path, "rb") as f:
                header = f.read(16)
                if len(header) < 16:
                    return False

                created_at = float.fromhex(header[:8].hex())
                ttl = float.fromhex(header[8:16].hex())

                if ttl > 0 and time.time() > (created_at + ttl):
                    # Expired
                    try:
                        file_path.unlink()
                    except:
                        pass
                    return False

            return True

        except Exception as e:
            self.logger.error(f"File cache exists error for key '{key}': {e}")
            return False

    async def clear(self) -> bool:
        """Clear all cache files"""
        try:
            for file_path in self.cache_dir.glob("*.cache"):
                try:
                    file_path.unlink()
                except:
                    pass

            # Reset stats
            self.stats = {k: 0 for k in self.stats.keys()}
            return True

        except Exception as e:
            self.logger.error(f"File cache clear error: {e}")
            return False

    def get_statistics(self) -> Dict[str, Any]:
        """Get cache statistics"""
        stats = self.stats.copy()

        # Add calculated metrics
        total_operations = stats["hits"] + stats["misses"]
        if total_operations > 0:
            stats["hit_ratio"] = stats["hits"] / total_operations
        else:
            stats["hit_ratio"] = 0.0

        # Add file count and directory size
        try:
            cache_files = list(self.cache_dir.glob("*.cache"))
            stats["file_count"] = len(cache_files)
            stats["total_size"] = sum(f.stat().st_size for f in cache_files)
        except:
            stats["file_count"] = 0
            stats["total_size"] = 0

        return stats
