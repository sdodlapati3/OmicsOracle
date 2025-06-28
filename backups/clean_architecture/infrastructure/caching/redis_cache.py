"""
Redis-based Distributed Caching Implementation
"""

import asyncio
import hashlib
import json
import logging
import pickle
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Union

import redis.asyncio as redis
from redis.asyncio import ConnectionPool


class CacheLevel(Enum):
    """Cache levels in hierarchy"""

    L1_MEMORY = 1  # In-memory cache (fastest)
    L2_REDIS = 2  # Redis cache (fast, distributed)
    L3_FILE = 3  # File cache (slower, persistent)


class SerializationMethod(Enum):
    """Serialization methods for cache values"""

    JSON = "json"
    PICKLE = "pickle"
    STRING = "string"


@dataclass
class CacheEntry:
    """Cache entry with metadata"""

    key: str
    value: Any
    created_at: float = field(default_factory=time.time)
    last_accessed: float = field(default_factory=time.time)
    access_count: int = 0
    ttl: Optional[float] = None
    serialization: SerializationMethod = SerializationMethod.PICKLE
    size_bytes: int = 0
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        """Check if entry has expired"""
        if self.ttl is None:
            return False
        return time.time() > (self.created_at + self.ttl)

    def update_access(self):
        """Update access statistics"""
        self.last_accessed = time.time()
        self.access_count += 1


class RedisCache:
    """
    Advanced Redis-based caching with connection pooling and failover
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379",
        max_connections: int = 50,
        retry_on_timeout: bool = True,
        socket_timeout: int = 5,
        socket_connect_timeout: int = 5,
        default_ttl: int = 3600,
        key_prefix: str = "omics_oracle:",
        serialization: SerializationMethod = SerializationMethod.PICKLE,
    ):
        self.redis_url = redis_url
        self.max_connections = max_connections
        self.retry_on_timeout = retry_on_timeout
        self.socket_timeout = socket_timeout
        self.socket_connect_timeout = socket_connect_timeout
        self.default_ttl = default_ttl
        self.key_prefix = key_prefix
        self.default_serialization = serialization

        # Connection pool
        self._pool: Optional[ConnectionPool] = None
        self._redis: Optional[redis.Redis] = None

        # Cache statistics
        self.stats = {
            "hits": 0,
            "misses": 0,
            "sets": 0,
            "deletes": 0,
            "errors": 0,
            "evictions": 0,
            "memory_usage": 0,
        }

        # Connection health
        self._connection_healthy = True
        self._last_health_check = 0
        self._health_check_interval = 60  # 1 minute

        # Batch operations
        self._batch_operations: List[Dict] = []
        self._batch_size = 100

        self.logger = logging.getLogger(__name__)

    async def connect(self):
        """Initialize Redis connection with pool"""
        try:
            # Create connection pool
            self._pool = ConnectionPool.from_url(
                self.redis_url,
                max_connections=self.max_connections,
                retry_on_timeout=self.retry_on_timeout,
                socket_timeout=self.socket_timeout,
                socket_connect_timeout=self.socket_connect_timeout,
                decode_responses=False,  # Keep binary for pickle
            )

            # Create Redis client
            self._redis = redis.Redis(connection_pool=self._pool)

            # Test connection
            await self._redis.ping()
            self._connection_healthy = True

            self.logger.info(f"Redis cache connected: {self.redis_url}")

        except Exception as e:
            self.logger.error(f"Failed to connect to Redis: {e}")
            self._connection_healthy = False
            raise

    async def disconnect(self):
        """Close Redis connection"""
        if self._redis:
            await self._redis.close()

        if self._pool:
            await self._pool.disconnect()

        self.logger.info("Redis cache disconnected")

    async def health_check(self) -> bool:
        """Check Redis connection health"""
        current_time = time.time()

        # Throttle health checks
        if current_time - self._last_health_check < self._health_check_interval:
            return self._connection_healthy

        try:
            if self._redis:
                await self._redis.ping()
                self._connection_healthy = True
            else:
                self._connection_healthy = False
        except Exception as e:
            self.logger.warning(f"Redis health check failed: {e}")
            self._connection_healthy = False

        self._last_health_check = current_time
        return self._connection_healthy

    def _make_key(self, key: str) -> str:
        """Create prefixed cache key"""
        return f"{self.key_prefix}{key}"

    def _serialize_value(self, value: Any, method: SerializationMethod) -> bytes:
        """Serialize value for storage"""
        if method == SerializationMethod.JSON:
            return json.dumps(value, default=str).encode("utf-8")
        elif method == SerializationMethod.PICKLE:
            return pickle.dumps(value)
        elif method == SerializationMethod.STRING:
            return str(value).encode("utf-8")
        else:
            return pickle.dumps(value)

    def _deserialize_value(self, data: bytes, method: SerializationMethod) -> Any:
        """Deserialize value from storage"""
        if method == SerializationMethod.JSON:
            return json.loads(data.decode("utf-8"))
        elif method == SerializationMethod.PICKLE:
            return pickle.loads(data)
        elif method == SerializationMethod.STRING:
            return data.decode("utf-8")
        else:
            return pickle.loads(data)

    async def get(self, key: str, default: Any = None, update_stats: bool = True) -> Any:
        """
        Get value from cache
        """
        if not await self.health_check():
            return default

        try:
            cache_key = self._make_key(key)

            # Get value and metadata
            pipe = self._redis.pipeline()
            pipe.hget(cache_key, "value")
            pipe.hget(cache_key, "serialization")
            pipe.hget(cache_key, "created_at")
            pipe.hget(cache_key, "ttl")
            pipe.hincrby(cache_key, "access_count", 1)
            pipe.hset(cache_key, "last_accessed", time.time())

            results = await pipe.execute()
            value_data, serialization_data, created_at_data, ttl_data = results[:4]

            if value_data is None:
                if update_stats:
                    self.stats["misses"] += 1
                return default

            # Check TTL
            if ttl_data and created_at_data:
                created_at = float(created_at_data)
                ttl = float(ttl_data)
                if time.time() > (created_at + ttl):
                    # Expired, delete and return default
                    await self.delete(key)
                    if update_stats:
                        self.stats["misses"] += 1
                    return default

            # Deserialize value
            serialization = (
                SerializationMethod(serialization_data.decode("utf-8"))
                if serialization_data
                else self.default_serialization
            )
            value = self._deserialize_value(value_data, serialization)

            if update_stats:
                self.stats["hits"] += 1

            return value

        except Exception as e:
            self.logger.error(f"Redis get error for key '{key}': {e}")
            self.stats["errors"] += 1
            return default

    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None,
        serialization: Optional[SerializationMethod] = None,
        tags: Optional[List[str]] = None,
    ) -> bool:
        """
        Set value in cache
        """
        if not await self.health_check():
            return False

        try:
            cache_key = self._make_key(key)

            # Use default values
            if ttl is None:
                ttl = self.default_ttl
            if serialization is None:
                serialization = self.default_serialization
            if tags is None:
                tags = []

            # Serialize value
            serialized_value = self._serialize_value(value, serialization)

            # Prepare cache entry data
            current_time = time.time()
            entry_data = {
                "value": serialized_value,
                "serialization": serialization.value,
                "created_at": current_time,
                "last_accessed": current_time,
                "access_count": 0,
                "ttl": ttl,
                "size_bytes": len(serialized_value),
                "tags": json.dumps(tags),
            }

            # Store with pipeline
            pipe = self._redis.pipeline()
            pipe.hset(cache_key, mapping=entry_data)

            # Set expiration if TTL is specified
            if ttl and ttl > 0:
                pipe.expire(cache_key, ttl)

            # Add to tag indices
            for tag in tags:
                tag_key = self._make_key(f"tag:{tag}")
                pipe.sadd(tag_key, key)
                if ttl and ttl > 0:
                    pipe.expire(tag_key, ttl + 3600)  # Tag index lives longer

            await pipe.execute()

            self.stats["sets"] += 1
            return True

        except Exception as e:
            self.logger.error(f"Redis set error for key '{key}': {e}")
            self.stats["errors"] += 1
            return False

    async def delete(self, key: str) -> bool:
        """
        Delete value from cache
        """
        if not await self.health_check():
            return False

        try:
            cache_key = self._make_key(key)

            # Get tags before deletion
            tags_data = await self._redis.hget(cache_key, "tags")

            # Delete main key
            result = await self._redis.delete(cache_key)

            # Remove from tag indices
            if tags_data:
                try:
                    tags = json.loads(tags_data.decode("utf-8"))
                    pipe = self._redis.pipeline()
                    for tag in tags:
                        tag_key = self._make_key(f"tag:{tag}")
                        pipe.srem(tag_key, key)
                    await pipe.execute()
                except Exception:
                    pass  # Ignore tag cleanup errors

            if result > 0:
                self.stats["deletes"] += 1
                return True
            return False

        except Exception as e:
            self.logger.error(f"Redis delete error for key '{key}': {e}")
            self.stats["errors"] += 1
            return False

    async def exists(self, key: str) -> bool:
        """
        Check if key exists in cache
        """
        if not await self.health_check():
            return False

        try:
            cache_key = self._make_key(key)
            return bool(await self._redis.exists(cache_key))
        except Exception as e:
            self.logger.error(f"Redis exists error for key '{key}': {e}")
            return False

    async def clear_by_tag(self, tag: str) -> int:
        """
        Clear all cache entries with a specific tag
        """
        if not await self.health_check():
            return 0

        try:
            tag_key = self._make_key(f"tag:{tag}")

            # Get all keys with this tag
            keys = await self._redis.smembers(tag_key)

            if not keys:
                return 0

            # Delete all keys
            pipe = self._redis.pipeline()
            for key in keys:
                cache_key = self._make_key(key.decode("utf-8"))
                pipe.delete(cache_key)

            # Delete tag index
            pipe.delete(tag_key)

            results = await pipe.execute()
            deleted_count = sum(1 for result in results[:-1] if result > 0)

            self.stats["deletes"] += deleted_count
            return deleted_count

        except Exception as e:
            self.logger.error(f"Redis clear_by_tag error for tag '{tag}': {e}")
            self.stats["errors"] += 1
            return 0

    async def clear_all(self) -> bool:
        """
        Clear all cache entries with our prefix
        """
        if not await self.health_check():
            return False

        try:
            pattern = f"{self.key_prefix}*"

            # Use scan for memory efficiency
            deleted_count = 0
            async for key in self._redis.scan_iter(match=pattern, count=1000):
                await self._redis.delete(key)
                deleted_count += 1

            self.stats["deletes"] += deleted_count
            return True

        except Exception as e:
            self.logger.error(f"Redis clear_all error: {e}")
            self.stats["errors"] += 1
            return False

    async def get_keys(self, pattern: str = "*") -> List[str]:
        """
        Get all keys matching pattern (without prefix)
        """
        if not await self.health_check():
            return []

        try:
            full_pattern = f"{self.key_prefix}{pattern}"
            keys = []

            async for key in self._redis.scan_iter(match=full_pattern, count=1000):
                # Remove prefix
                key_str = key.decode("utf-8")
                if key_str.startswith(self.key_prefix):
                    clean_key = key_str[len(self.key_prefix) :]
                    keys.append(clean_key)

            return keys

        except Exception as e:
            self.logger.error(f"Redis get_keys error: {e}")
            return []

    async def get_info(self, key: str) -> Optional[Dict[str, Any]]:
        """
        Get metadata about a cache entry
        """
        if not await self.health_check():
            return None

        try:
            cache_key = self._make_key(key)

            # Get all metadata
            entry_data = await self._redis.hgetall(cache_key)

            if not entry_data:
                return None

            # Convert to dict with proper types
            info = {}
            for field, value in entry_data.items():
                field_str = field.decode("utf-8")

                if field_str in ["created_at", "last_accessed", "ttl"]:
                    info[field_str] = float(value) if value else None
                elif field_str in ["access_count", "size_bytes"]:
                    info[field_str] = int(value) if value else 0
                elif field_str == "tags":
                    try:
                        info[field_str] = json.loads(value.decode("utf-8"))
                    except Exception:
                        info[field_str] = []
                else:
                    info[field_str] = value.decode("utf-8") if value else None

            return info

        except Exception as e:
            self.logger.error(f"Redis get_info error for key '{key}': {e}")
            return None

    async def batch_get(self, keys: List[str]) -> Dict[str, Any]:
        """
        Get multiple values in a single operation
        """
        if not await self.health_check():
            return {}

        try:
            pipe = self._redis.pipeline()

            # Queue all get operations
            for key in keys:
                cache_key = self._make_key(key)
                pipe.hgetall(cache_key)

            results = await pipe.execute()

            # Process results
            batch_results = {}
            for i, (key, result) in enumerate(zip(keys, results)):
                if not result:
                    self.stats["misses"] += 1
                    continue

                try:
                    # Check TTL
                    created_at = float(result.get(b"created_at", 0))
                    ttl = float(result.get(b"ttl", 0))

                    if ttl > 0 and time.time() > (created_at + ttl):
                        # Expired
                        self.stats["misses"] += 1
                        continue

                    # Deserialize
                    value_data = result.get(b"value")
                    serialization_data = result.get(b"serialization", b"pickle")

                    if value_data:
                        serialization = SerializationMethod(serialization_data.decode("utf-8"))
                        value = self._deserialize_value(value_data, serialization)
                        batch_results[key] = value
                        self.stats["hits"] += 1
                    else:
                        self.stats["misses"] += 1

                except Exception as e:
                    self.logger.error(f"Error processing batch result for key '{key}': {e}")
                    self.stats["misses"] += 1

            return batch_results

        except Exception as e:
            self.logger.error(f"Redis batch_get error: {e}")
            self.stats["errors"] += 1
            return {}

    async def batch_set(self, items: Dict[str, Any], ttl: Optional[int] = None) -> int:
        """
        Set multiple values in a single operation
        """
        if not await self.health_check():
            return 0

        try:
            pipe = self._redis.pipeline()

            # Use default TTL
            if ttl is None:
                ttl = self.default_ttl

            current_time = time.time()
            success_count = 0

            for key, value in items.items():
                try:
                    cache_key = self._make_key(key)

                    # Serialize value
                    serialized_value = self._serialize_value(value, self.default_serialization)

                    # Prepare entry data
                    entry_data = {
                        "value": serialized_value,
                        "serialization": self.default_serialization.value,
                        "created_at": current_time,
                        "last_accessed": current_time,
                        "access_count": 0,
                        "ttl": ttl,
                        "size_bytes": len(serialized_value),
                        "tags": "[]",
                    }

                    pipe.hset(cache_key, mapping=entry_data)

                    if ttl and ttl > 0:
                        pipe.expire(cache_key, ttl)

                    success_count += 1

                except Exception as e:
                    self.logger.error(f"Error preparing batch set for key '{key}': {e}")

            # Execute batch
            await pipe.execute()

            self.stats["sets"] += success_count
            return success_count

        except Exception as e:
            self.logger.error(f"Redis batch_set error: {e}")
            self.stats["errors"] += 1
            return 0

    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get cache statistics including Redis info
        """
        stats = self.stats.copy()

        # Add calculated metrics
        total_operations = stats["hits"] + stats["misses"]
        if total_operations > 0:
            stats["hit_ratio"] = stats["hits"] / total_operations
        else:
            stats["hit_ratio"] = 0.0

        # Get Redis info if connected
        if await self.health_check():
            try:
                redis_info = await self._redis.info("memory")
                stats["redis_memory_used"] = redis_info.get("used_memory", 0)
                stats["redis_memory_peak"] = redis_info.get("used_memory_peak", 0)
                stats["redis_memory_rss"] = redis_info.get("used_memory_rss", 0)

                # Get key count
                stats["redis_key_count"] = await self._redis.dbsize()

            except Exception as e:
                self.logger.error(f"Error getting Redis statistics: {e}")

        stats["connection_healthy"] = self._connection_healthy
        return stats


# Global Redis cache instance
redis_cache = RedisCache()
