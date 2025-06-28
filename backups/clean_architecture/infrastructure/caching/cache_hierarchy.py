"""
Multi-Level Cache Hierarchy with L1 (Memory), L2 (Redis), L3 (File) Caching
"""

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Union

from .file_cache import FileCache
from .memory_cache import MemoryCache  # From Phase 5
from .redis_cache import CacheLevel, RedisCache, SerializationMethod


@dataclass
class CacheStats:
    """Cache statistics for each level"""

    level: CacheLevel
    hits: int = 0
    misses: int = 0
    sets: int = 0
    deletes: int = 0
    errors: int = 0
    size: int = 0
    memory_usage: int = 0

    @property
    def hit_ratio(self) -> float:
        """Calculate hit ratio"""
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0


@dataclass
class CacheOperation:
    """Cache operation for promotion/demotion"""

    operation: str  # "promote", "demote", "evict"
    key: str
    value: Any = None
    from_level: Optional[CacheLevel] = None
    to_level: Optional[CacheLevel] = None
    reason: str = ""
    timestamp: float = field(default_factory=time.time)


class CachePromotionPolicy(Enum):
    """Cache promotion policies"""

    ACCESS_COUNT = "access_count"  # Promote based on access frequency
    RECENT_ACCESS = "recent_access"  # Promote recently accessed items
    SIZE_AWARE = "size_aware"  # Consider item size in promotion
    ADAPTIVE = "adaptive"  # Adaptive promotion based on patterns


class CacheHierarchy:
    """
    Multi-level cache hierarchy with intelligent promotion/demotion
    """

    def __init__(
        self,
        memory_cache_size: int = 1000,
        redis_url: str = "redis://localhost:6379",
        file_cache_dir: str = "data/cache",
        promotion_policy: CachePromotionPolicy = CachePromotionPolicy.ADAPTIVE,
        auto_promotion: bool = True,
        promotion_threshold: int = 3,
        max_promotion_size: int = 1024 * 1024,
    ):  # 1MB
        self.promotion_policy = promotion_policy
        self.auto_promotion = auto_promotion
        self.promotion_threshold = promotion_threshold
        self.max_promotion_size = max_promotion_size

        # Initialize cache levels
        self._l1_memory = MemoryCache(default_ttl=3600)  # 1 hour TTL
        self._l2_redis = RedisCache(redis_url=redis_url)
        self._l3_file = FileCache(cache_dir=file_cache_dir)

        # Cache statistics
        self._stats = {
            CacheLevel.L1_MEMORY: CacheStats(CacheLevel.L1_MEMORY),
            CacheLevel.L2_REDIS: CacheStats(CacheLevel.L2_REDIS),
            CacheLevel.L3_FILE: CacheStats(CacheLevel.L3_FILE),
        }

        # Access tracking for promotion decisions
        self._access_patterns: Dict[str, Dict[str, Any]] = {}

        # Promotion/demotion queue
        self._promotion_queue: List[CacheOperation] = []
        self._promotion_task: Optional[asyncio.Task] = None

        # Performance metrics
        self._performance_metrics = {
            "total_operations": 0,
            "l1_hit_ratio": 0.0,
            "l2_hit_ratio": 0.0,
            "l3_hit_ratio": 0.0,
            "overall_hit_ratio": 0.0,
            "average_latency": 0.0,
            "promotions": 0,
            "demotions": 0,
            "evictions": 0,
        }

        self.logger = logging.getLogger(__name__)

    @property
    def l1_cache(self) -> MemoryCache:
        """Access L1 memory cache"""
        return self._l1_memory

    @property
    def l2_cache(self) -> RedisCache:
        """Access L2 Redis cache"""
        return self._l2_redis

    @property
    def l3_cache(self) -> FileCache:
        """Access L3 file cache"""
        return self._l3_file

    async def start(self):
        """Initialize cache hierarchy"""
        self.logger.info("Starting cache hierarchy")

        # Connect to Redis
        await self._l2_redis.connect()

        # Start promotion task
        if self.auto_promotion:
            self._promotion_task = asyncio.create_task(self._promotion_worker())

        self.logger.info("Cache hierarchy started")

    async def stop(self):
        """Shutdown cache hierarchy"""
        self.logger.info("Stopping cache hierarchy")

        # Stop promotion task
        if self._promotion_task:
            self._promotion_task.cancel()
            try:
                await self._promotion_task
            except asyncio.CancelledError:
                pass

        # Disconnect from Redis
        await self._l2_redis.disconnect()

        self.logger.info("Cache hierarchy stopped")

    async def get(self, key: str, default: Any = None, promote_on_hit: bool = True) -> Any:
        """
        Get value from cache hierarchy (L1 → L2 → L3)
        """
        start_time = time.time()
        self._performance_metrics["total_operations"] += 1

        # Track access
        self._track_access(key)

        # Try L1 (Memory) cache first
        value = await self._l1_memory.get(key)
        if value is not None:
            self._stats[CacheLevel.L1_MEMORY].hits += 1
            self._update_performance_metrics(start_time, CacheLevel.L1_MEMORY)
            return value

        self._stats[CacheLevel.L1_MEMORY].misses += 1

        # Try L2 (Redis) cache
        value = await self._l2_redis.get(key)
        if value is not None:
            self._stats[CacheLevel.L2_REDIS].hits += 1

            # Promote to L1 if policy allows
            if promote_on_hit and self._should_promote(key, CacheLevel.L2_REDIS, CacheLevel.L1_MEMORY):
                await self._promote_value(key, value, CacheLevel.L2_REDIS, CacheLevel.L1_MEMORY)

            self._update_performance_metrics(start_time, CacheLevel.L2_REDIS)
            return value

        self._stats[CacheLevel.L2_REDIS].misses += 1

        # Try L3 (File) cache
        value = await self._l3_file.get(key)
        if value is not None:
            self._stats[CacheLevel.L3_FILE].hits += 1

            # Promote to higher levels if policy allows
            if promote_on_hit:
                if self._should_promote(key, CacheLevel.L3_FILE, CacheLevel.L2_REDIS):
                    await self._promote_value(key, value, CacheLevel.L3_FILE, CacheLevel.L2_REDIS)

                    if self._should_promote(key, CacheLevel.L2_REDIS, CacheLevel.L1_MEMORY):
                        await self._promote_value(
                            key,
                            value,
                            CacheLevel.L2_REDIS,
                            CacheLevel.L1_MEMORY,
                        )

            self._update_performance_metrics(start_time, CacheLevel.L3_FILE)
            return value

        self._stats[CacheLevel.L3_FILE].misses += 1
        self._update_performance_metrics(start_time, None)

        return default

    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None,
        target_level: Optional[CacheLevel] = None,
        propagate: bool = True,
    ) -> bool:
        """
        Set value in cache hierarchy
        """
        # Determine target level
        if target_level is None:
            target_level = self._determine_initial_level(key, value)

        success = False

        # Set in target level
        if target_level == CacheLevel.L1_MEMORY:
            success = await self._l1_memory.set(key, value, ttl)
            if success:
                self._stats[CacheLevel.L1_MEMORY].sets += 1

        elif target_level == CacheLevel.L2_REDIS:
            success = await self._l2_redis.set(key, value, ttl)
            if success:
                self._stats[CacheLevel.L2_REDIS].sets += 1

        elif target_level == CacheLevel.L3_FILE:
            success = await self._l3_file.set(key, value, ttl)
            if success:
                self._stats[CacheLevel.L3_FILE].sets += 1

        # Propagate to lower levels if requested
        if success and propagate:
            await self._propagate_to_lower_levels(key, value, ttl, target_level)

        # Initialize access tracking
        if success:
            self._init_access_tracking(key, target_level)

        return success

    async def delete(self, key: str, all_levels: bool = True) -> bool:
        """
        Delete value from cache hierarchy
        """
        success = False

        if all_levels:
            # Delete from all levels
            l1_success = await self._l1_memory.delete(key)
            l2_success = await self._l2_redis.delete(key)
            l3_success = await self._l3_file.delete(key)

            success = l1_success or l2_success or l3_success

            if l1_success:
                self._stats[CacheLevel.L1_MEMORY].deletes += 1
            if l2_success:
                self._stats[CacheLevel.L2_REDIS].deletes += 1
            if l3_success:
                self._stats[CacheLevel.L3_FILE].deletes += 1

        else:
            # Delete from where it exists
            if await self._l1_memory.exists(key):
                success = await self._l1_memory.delete(key)
                if success:
                    self._stats[CacheLevel.L1_MEMORY].deletes += 1

            elif await self._l2_redis.exists(key):
                success = await self._l2_redis.delete(key)
                if success:
                    self._stats[CacheLevel.L2_REDIS].deletes += 1

            elif await self._l3_file.exists(key):
                success = await self._l3_file.delete(key)
                if success:
                    self._stats[CacheLevel.L3_FILE].deletes += 1

        # Remove access tracking
        if success and key in self._access_patterns:
            del self._access_patterns[key]

        return success

    async def clear_level(self, level: CacheLevel) -> bool:
        """
        Clear specific cache level
        """
        if level == CacheLevel.L1_MEMORY:
            success = await self._l1_memory.clear()
        elif level == CacheLevel.L2_REDIS:
            success = await self._l2_redis.clear_all()
        elif level == CacheLevel.L3_FILE:
            success = await self._l3_file.clear()
        else:
            return False

        if success:
            self._stats[level] = CacheStats(level)

        return success

    async def clear_all(self) -> bool:
        """
        Clear all cache levels
        """
        l1_success = await self.clear_level(CacheLevel.L1_MEMORY)
        l2_success = await self.clear_level(CacheLevel.L2_REDIS)
        l3_success = await self.clear_level(CacheLevel.L3_FILE)

        # Clear access patterns
        self._access_patterns.clear()

        return l1_success and l2_success and l3_success

    def _track_access(self, key: str):
        """Track access pattern for promotion decisions"""
        current_time = time.time()

        if key not in self._access_patterns:
            self._access_patterns[key] = {
                "access_count": 0,
                "last_access": current_time,
                "first_access": current_time,
                "access_frequency": 0.0,
                "size_estimate": 0,
            }

        pattern = self._access_patterns[key]
        pattern["access_count"] += 1
        pattern["last_access"] = current_time

        # Calculate frequency (accesses per hour)
        time_diff = current_time - pattern["first_access"]
        if time_diff > 0:
            pattern["access_frequency"] = pattern["access_count"] / (time_diff / 3600)

    def _init_access_tracking(self, key: str, level: CacheLevel):
        """Initialize access tracking for a new cache entry"""
        if key not in self._access_patterns:
            self._access_patterns[key] = {
                "access_count": 1,
                "last_access": time.time(),
                "first_access": time.time(),
                "access_frequency": 0.0,
                "size_estimate": 0,
                "current_level": level,
            }

    def _should_promote(self, key: str, from_level: CacheLevel, to_level: CacheLevel) -> bool:
        """
        Determine if a cache entry should be promoted
        """
        if not self.auto_promotion:
            return False

        pattern = self._access_patterns.get(key, {})
        access_count = pattern.get("access_count", 0)

        # Basic threshold check
        if access_count < self.promotion_threshold:
            return False

        # Size check
        size_estimate = pattern.get("size_estimate", 0)
        if size_estimate > self.max_promotion_size:
            return False

        # Policy-specific checks
        if self.promotion_policy == CachePromotionPolicy.ACCESS_COUNT:
            return access_count >= self.promotion_threshold

        elif self.promotion_policy == CachePromotionPolicy.RECENT_ACCESS:
            last_access = pattern.get("last_access", 0)
            return (time.time() - last_access) < 300  # 5 minutes

        elif self.promotion_policy == CachePromotionPolicy.SIZE_AWARE:
            # Prefer smaller items for promotion to L1
            if to_level == CacheLevel.L1_MEMORY:
                return size_estimate < 10240  # 10KB
            return True

        elif self.promotion_policy == CachePromotionPolicy.ADAPTIVE:
            # Adaptive policy considers multiple factors
            score = self._calculate_promotion_score(pattern, from_level, to_level)
            return score > 0.7  # Threshold for promotion

        return False

    def _calculate_promotion_score(
        self,
        pattern: Dict[str, Any],
        from_level: CacheLevel,
        to_level: CacheLevel,
    ) -> float:
        """
        Calculate promotion score for adaptive policy
        """
        score = 0.0

        # Access frequency factor (0-0.4)
        frequency = pattern.get("access_frequency", 0)
        score += min(frequency / 10, 0.4)  # Normalize to 0-0.4

        # Recency factor (0-0.3)
        last_access = pattern.get("last_access", 0)
        recency = max(0, 1 - (time.time() - last_access) / 3600)  # 1 hour decay
        score += recency * 0.3

        # Size factor (0-0.3)
        size_estimate = pattern.get("size_estimate", 0)
        if to_level == CacheLevel.L1_MEMORY:
            size_factor = max(0, 1 - size_estimate / self.max_promotion_size)
            score += size_factor * 0.3
        else:
            score += 0.3  # No size penalty for L2/L3

        return score

    def _determine_initial_level(self, key: str, value: Any) -> CacheLevel:
        """
        Determine initial cache level for new entries
        """
        # Estimate size
        try:
            size_estimate = len(str(value))  # Simple size estimation
        except Exception:
            size_estimate = 1000  # Default estimate

        # Small items go to L1
        if size_estimate < 1024:  # 1KB
            return CacheLevel.L1_MEMORY

        # Medium items go to L2
        elif size_estimate < 1024 * 1024:  # 1MB
            return CacheLevel.L2_REDIS

        # Large items go to L3
        else:
            return CacheLevel.L3_FILE

    async def _promote_value(self, key: str, value: Any, from_level: CacheLevel, to_level: CacheLevel):
        """
        Promote value between cache levels
        """
        try:
            # Set in target level
            if to_level == CacheLevel.L1_MEMORY:
                success = await self._l1_memory.set(key, value)
            elif to_level == CacheLevel.L2_REDIS:
                success = await self._l2_redis.set(key, value)
            elif to_level == CacheLevel.L3_FILE:
                success = await self._l3_file.set(key, value)
            else:
                success = False

            if success:
                # Update access pattern
                if key in self._access_patterns:
                    self._access_patterns[key]["current_level"] = to_level

                # Update metrics
                self._performance_metrics["promotions"] += 1

                self.logger.debug(f"Promoted cache key '{key}' from {from_level.name} to {to_level.name}")

        except Exception as e:
            self.logger.error(f"Error promoting cache key '{key}': {e}")

    async def _propagate_to_lower_levels(
        self, key: str, value: Any, ttl: Optional[int], from_level: CacheLevel
    ):
        """
        Propagate cache entry to lower levels
        """
        if from_level == CacheLevel.L1_MEMORY:
            # Propagate to L2 and L3
            await self._l2_redis.set(key, value, ttl)
            await self._l3_file.set(key, value, ttl)

        elif from_level == CacheLevel.L2_REDIS:
            # Propagate to L3 only
            await self._l3_file.set(key, value, ttl)

    async def _promotion_worker(self):
        """
        Background worker for processing promotion/demotion operations
        """
        while True:
            try:
                # Process promotion queue
                if self._promotion_queue:
                    operation = self._promotion_queue.pop(0)
                    await self._process_cache_operation(operation)

                # Periodic promotion analysis
                await self._analyze_promotion_candidates()

                # Wait before next iteration
                await asyncio.sleep(30)  # Run every 30 seconds

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Promotion worker error: {e}")
                await asyncio.sleep(30)

    async def _process_cache_operation(self, operation: CacheOperation):
        """
        Process a cache operation (promote/demote/evict)
        """
        try:
            if operation.operation == "promote":
                await self._promote_value(
                    operation.key,
                    operation.value,
                    operation.from_level,
                    operation.to_level,
                )

            elif operation.operation == "demote":
                # Remove from higher level
                if operation.from_level == CacheLevel.L1_MEMORY:
                    await self._l1_memory.delete(operation.key)
                elif operation.from_level == CacheLevel.L2_REDIS:
                    await self._l2_redis.delete(operation.key)

                self._performance_metrics["demotions"] += 1

            elif operation.operation == "evict":
                # Remove from specified level
                if operation.from_level == CacheLevel.L1_MEMORY:
                    await self._l1_memory.delete(operation.key)
                elif operation.from_level == CacheLevel.L2_REDIS:
                    await self._l2_redis.delete(operation.key)
                elif operation.from_level == CacheLevel.L3_FILE:
                    await self._l3_file.delete(operation.key)

                self._performance_metrics["evictions"] += 1

        except Exception as e:
            self.logger.error(f"Error processing cache operation: {e}")

    async def _analyze_promotion_candidates(self):
        """
        Analyze access patterns to identify promotion candidates
        """
        current_time = time.time()

        for key, pattern in list(self._access_patterns.items()):
            try:
                current_level = pattern.get("current_level", CacheLevel.L3_FILE)

                # Check for promotion opportunities
                if current_level == CacheLevel.L3_FILE:
                    if self._should_promote(key, CacheLevel.L3_FILE, CacheLevel.L2_REDIS):
                        # Get value for promotion
                        value = await self._l3_file.get(key)
                        if value is not None:
                            operation = CacheOperation(
                                operation="promote",
                                key=key,
                                value=value,
                                from_level=CacheLevel.L3_FILE,
                                to_level=CacheLevel.L2_REDIS,
                                reason="access_pattern_analysis",
                            )
                            self._promotion_queue.append(operation)

                elif current_level == CacheLevel.L2_REDIS:
                    if self._should_promote(key, CacheLevel.L2_REDIS, CacheLevel.L1_MEMORY):
                        # Get value for promotion
                        value = await self._l2_redis.get(key)
                        if value is not None:
                            operation = CacheOperation(
                                operation="promote",
                                key=key,
                                value=value,
                                from_level=CacheLevel.L2_REDIS,
                                to_level=CacheLevel.L1_MEMORY,
                                reason="access_pattern_analysis",
                            )
                            self._promotion_queue.append(operation)

                # Check for demotion opportunities (infrequently accessed items)
                last_access = pattern.get("last_access", current_time)
                if (current_time - last_access) > 3600:  # 1 hour without access
                    if current_level == CacheLevel.L1_MEMORY:
                        operation = CacheOperation(
                            operation="demote",
                            key=key,
                            from_level=CacheLevel.L1_MEMORY,
                            reason="infrequent_access",
                        )
                        self._promotion_queue.append(operation)

            except Exception as e:
                self.logger.error(f"Error analyzing promotion for key '{key}': {e}")

    def _update_performance_metrics(self, start_time: float, hit_level: Optional[CacheLevel]):
        """
        Update performance metrics
        """
        # Update latency
        latency = time.time() - start_time
        current_avg = self._performance_metrics["average_latency"]
        operations = self._performance_metrics["total_operations"]

        # Rolling average
        self._performance_metrics["average_latency"] = (current_avg * (operations - 1) + latency) / operations

        # Update hit ratios
        for level in CacheLevel:
            stats = self._stats[level]
            self._performance_metrics[f"{level.name.lower()}_hit_ratio"] = stats.hit_ratio

        # Overall hit ratio
        total_hits = sum(stats.hits for stats in self._stats.values())
        total_operations = sum(stats.hits + stats.misses for stats in self._stats.values())

        if total_operations > 0:
            self._performance_metrics["overall_hit_ratio"] = total_hits / total_operations

    # Information and statistics
    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive cache hierarchy statistics
        """
        stats = {}

        # Level-specific statistics
        for level, cache_stats in self._stats.items():
            level_name = level.name.lower()
            stats[level_name] = {
                "hits": cache_stats.hits,
                "misses": cache_stats.misses,
                "sets": cache_stats.sets,
                "deletes": cache_stats.deletes,
                "errors": cache_stats.errors,
                "hit_ratio": cache_stats.hit_ratio,
            }

        # Redis-specific stats
        if await self._l2_redis.health_check():
            redis_stats = await self._l2_redis.get_statistics()
            stats["l2_redis"]["redis_info"] = redis_stats

        # Performance metrics
        stats["performance"] = self._performance_metrics.copy()

        # Access pattern statistics
        stats["access_patterns"] = {
            "tracked_keys": len(self._access_patterns),
            "promotion_queue_size": len(self._promotion_queue),
            "average_access_frequency": sum(
                p.get("access_frequency", 0) for p in self._access_patterns.values()
            )
            / max(len(self._access_patterns), 1),
        }

        return stats

    async def get_key_info(self, key: str) -> Optional[Dict[str, Any]]:
        """
        Get information about where a key is cached
        """
        info = {
            "key": key,
            "levels": [],
            "access_pattern": self._access_patterns.get(key, {}),
        }

        # Check each level
        if await self._l1_memory.exists(key):
            info["levels"].append("L1_MEMORY")

        if await self._l2_redis.exists(key):
            info["levels"].append("L2_REDIS")
            redis_info = await self._l2_redis.get_info(key)
            if redis_info:
                info["redis_info"] = redis_info

        if await self._l3_file.exists(key):
            info["levels"].append("L3_FILE")

        return info if info["levels"] else None

    async def warm_cache(
        self,
        data: Dict[str, Any],
        target_level: CacheLevel = CacheLevel.L2_REDIS,
    ):
        """
        Warm cache with pre-computed data
        """
        self.logger.info(f"Warming cache with {len(data)} entries at level {target_level.name}")

        success_count = 0

        for key, value in data.items():
            try:
                if await self.set(key, value, target_level=target_level, propagate=False):
                    success_count += 1
            except Exception as e:
                self.logger.error(f"Error warming cache for key '{key}': {e}")

        self.logger.info(f"Cache warming completed: {success_count}/{len(data)} entries successful")
        return success_count


# Global cache hierarchy instance
cache_hierarchy = CacheHierarchy()
