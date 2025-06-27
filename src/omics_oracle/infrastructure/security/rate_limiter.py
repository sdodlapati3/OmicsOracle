"""
Advanced Rate Limiting Implementation

Provides sophisticated rate limiting with:
- Multiple rate limiting strategies (token bucket, sliding window, fixed window)
- Per-user and per-endpoint rate limiting
- Distributed rate limiting support
- Rate limit warming and bursting
"""

import asyncio
import hashlib
import logging
import time
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


class RateLimitStrategy(Enum):
    """Rate limiting strategy enumeration."""

    TOKEN_BUCKET = "token_bucket"
    SLIDING_WINDOW = "sliding_window"
    FIXED_WINDOW = "fixed_window"


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting."""

    requests_per_second: float = 10.0
    burst_size: int = 100
    window_size_seconds: int = 60
    strategy: RateLimitStrategy = RateLimitStrategy.TOKEN_BUCKET
    enable_warming: bool = True
    warming_period_seconds: int = 300  # 5 minutes


@dataclass
class RateLimitResult:
    """Result of rate limit check."""

    allowed: bool
    remaining: int
    reset_time: float
    retry_after: Optional[float] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class RateLimitBackend(ABC):
    """Abstract rate limit backend."""

    @abstractmethod
    async def check_rate_limit(
        self, key: str, config: RateLimitConfig
    ) -> RateLimitResult:
        """Check if request should be rate limited."""
        pass

    @abstractmethod
    async def reset_rate_limit(self, key: str) -> None:
        """Reset rate limit for a key."""
        pass

    @abstractmethod
    async def get_stats(self) -> Dict[str, Any]:
        """Get rate limiting statistics."""
        pass


class TokenBucketBackend(RateLimitBackend):
    """Token bucket rate limiting backend."""

    def __init__(self):
        self._buckets: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    async def check_rate_limit(
        self, key: str, config: RateLimitConfig
    ) -> RateLimitResult:
        """Check rate limit using token bucket algorithm."""
        async with self._lock:
            now = time.time()

            if key not in self._buckets:
                self._buckets[key] = {
                    "tokens": config.burst_size,
                    "last_update": now,
                    "requests": 0,
                }

            bucket = self._buckets[key]

            # Add tokens based on time passed
            time_passed = now - bucket["last_update"]
            tokens_to_add = time_passed * config.requests_per_second
            bucket["tokens"] = min(
                config.burst_size, bucket["tokens"] + tokens_to_add
            )
            bucket["last_update"] = now

            # Check if request can be allowed
            if bucket["tokens"] >= 1:
                bucket["tokens"] -= 1
                bucket["requests"] += 1

                return RateLimitResult(
                    allowed=True,
                    remaining=int(bucket["tokens"]),
                    reset_time=now
                    + (config.burst_size - bucket["tokens"])
                    / config.requests_per_second,
                    metadata={
                        "strategy": "token_bucket",
                        "tokens": bucket["tokens"],
                        "total_requests": bucket["requests"],
                    },
                )
            else:
                retry_after = (
                    1 - bucket["tokens"]
                ) / config.requests_per_second

                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    reset_time=now + retry_after,
                    retry_after=retry_after,
                    metadata={
                        "strategy": "token_bucket",
                        "tokens": bucket["tokens"],
                        "total_requests": bucket["requests"],
                    },
                )

    async def reset_rate_limit(self, key: str) -> None:
        """Reset rate limit for a key."""
        async with self._lock:
            if key in self._buckets:
                del self._buckets[key]

    async def get_stats(self) -> Dict[str, Any]:
        """Get rate limiting statistics."""
        async with self._lock:
            total_buckets = len(self._buckets)
            total_requests = sum(
                bucket["requests"] for bucket in self._buckets.values()
            )

            return {
                "backend_type": "token_bucket",
                "total_buckets": total_buckets,
                "total_requests": total_requests,
                "active_keys": list(self._buckets.keys()),
            }


class SlidingWindowBackend(RateLimitBackend):
    """Sliding window rate limiting backend."""

    def __init__(self):
        self._windows: Dict[str, deque] = {}
        self._lock = asyncio.Lock()

    async def check_rate_limit(
        self, key: str, config: RateLimitConfig
    ) -> RateLimitResult:
        """Check rate limit using sliding window algorithm."""
        async with self._lock:
            now = time.time()
            window_start = now - config.window_size_seconds

            if key not in self._windows:
                self._windows[key] = deque()

            window = self._windows[key]

            # Remove old requests outside the window
            while window and window[0] <= window_start:
                window.popleft()

            # Check if we can allow the request
            requests_in_window = len(window)
            max_requests = int(
                config.requests_per_second * config.window_size_seconds
            )

            if requests_in_window < max_requests:
                window.append(now)

                return RateLimitResult(
                    allowed=True,
                    remaining=max_requests - requests_in_window - 1,
                    reset_time=window[0] + config.window_size_seconds
                    if window
                    else now,
                    metadata={
                        "strategy": "sliding_window",
                        "requests_in_window": requests_in_window + 1,
                        "window_size": config.window_size_seconds,
                    },
                )
            else:
                # Calculate retry after based on oldest request in window
                retry_after = (window[0] + config.window_size_seconds) - now

                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    reset_time=window[0] + config.window_size_seconds,
                    retry_after=max(0, retry_after),
                    metadata={
                        "strategy": "sliding_window",
                        "requests_in_window": requests_in_window,
                        "window_size": config.window_size_seconds,
                    },
                )

    async def reset_rate_limit(self, key: str) -> None:
        """Reset rate limit for a key."""
        async with self._lock:
            if key in self._windows:
                del self._windows[key]

    async def get_stats(self) -> Dict[str, Any]:
        """Get rate limiting statistics."""
        async with self._lock:
            total_windows = len(self._windows)
            total_requests = sum(
                len(window) for window in self._windows.values()
            )

            return {
                "backend_type": "sliding_window",
                "total_windows": total_windows,
                "total_active_requests": total_requests,
                "active_keys": list(self._windows.keys()),
            }


class FixedWindowBackend(RateLimitBackend):
    """Fixed window rate limiting backend."""

    def __init__(self):
        self._windows: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    async def check_rate_limit(
        self, key: str, config: RateLimitConfig
    ) -> RateLimitResult:
        """Check rate limit using fixed window algorithm."""
        async with self._lock:
            now = time.time()
            window_start = (
                int(now // config.window_size_seconds)
                * config.window_size_seconds
            )
            window_end = window_start + config.window_size_seconds

            if key not in self._windows:
                self._windows[key] = {
                    "window_start": window_start,
                    "requests": 0,
                }

            window = self._windows[key]

            # Reset window if it has expired
            if window["window_start"] < window_start:
                window["window_start"] = window_start
                window["requests"] = 0

            max_requests = int(
                config.requests_per_second * config.window_size_seconds
            )

            if window["requests"] < max_requests:
                window["requests"] += 1

                return RateLimitResult(
                    allowed=True,
                    remaining=max_requests - window["requests"],
                    reset_time=window_end,
                    metadata={
                        "strategy": "fixed_window",
                        "requests_in_window": window["requests"],
                        "window_start": window_start,
                        "window_end": window_end,
                    },
                )
            else:
                retry_after = window_end - now

                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    reset_time=window_end,
                    retry_after=retry_after,
                    metadata={
                        "strategy": "fixed_window",
                        "requests_in_window": window["requests"],
                        "window_start": window_start,
                        "window_end": window_end,
                    },
                )

    async def reset_rate_limit(self, key: str) -> None:
        """Reset rate limit for a key."""
        async with self._lock:
            if key in self._windows:
                del self._windows[key]

    async def get_stats(self) -> Dict[str, Any]:
        """Get rate limiting statistics."""
        async with self._lock:
            total_windows = len(self._windows)
            total_requests = sum(
                window["requests"] for window in self._windows.values()
            )

            return {
                "backend_type": "fixed_window",
                "total_windows": total_windows,
                "total_requests": total_requests,
                "active_keys": list(self._windows.keys()),
            }


class RateLimiter:
    """Advanced rate limiter with multiple strategies."""

    def __init__(self, default_config: Optional[RateLimitConfig] = None):
        self.default_config = default_config or RateLimitConfig()
        self._backends = {
            RateLimitStrategy.TOKEN_BUCKET: TokenBucketBackend(),
            RateLimitStrategy.SLIDING_WINDOW: SlidingWindowBackend(),
            RateLimitStrategy.FIXED_WINDOW: FixedWindowBackend(),
        }
        self._per_key_configs: Dict[str, RateLimitConfig] = {}
        self._stats = {
            "total_requests": 0,
            "allowed_requests": 0,
            "blocked_requests": 0,
            "start_time": time.time(),
        }

    def configure_key(self, key: str, config: RateLimitConfig) -> None:
        """Configure rate limiting for a specific key."""
        self._per_key_configs[key] = config
        logger.info(f"Configured rate limiting for key: {key}")

    async def check_rate_limit(
        self, key: str, config: Optional[RateLimitConfig] = None
    ) -> RateLimitResult:
        """Check if request should be rate limited."""
        effective_config = (
            config or self._per_key_configs.get(key) or self.default_config
        )

        backend = self._backends[effective_config.strategy]
        result = await backend.check_rate_limit(key, effective_config)

        # Update statistics
        self._stats["total_requests"] += 1
        if result.allowed:
            self._stats["allowed_requests"] += 1
        else:
            self._stats["blocked_requests"] += 1

        return result

    async def reset_rate_limit(self, key: str) -> None:
        """Reset rate limit for a key across all backends."""
        for backend in self._backends.values():
            await backend.reset_rate_limit(key)

    def get_key_for_request(
        self,
        client_ip: str,
        user_id: Optional[str] = None,
        endpoint: Optional[str] = None,
    ) -> str:
        """Generate rate limit key for a request."""
        key_parts = [client_ip]

        if user_id:
            key_parts.append(f"user:{user_id}")

        if endpoint:
            key_parts.append(f"endpoint:{endpoint}")

        key = ":".join(key_parts)
        return hashlib.md5(key.encode()).hexdigest()

    async def get_comprehensive_stats(self) -> Dict[str, Any]:
        """Get comprehensive rate limiting statistics."""
        backend_stats = {}
        for strategy, backend in self._backends.items():
            backend_stats[strategy.value] = await backend.get_stats()

        uptime = time.time() - self._stats["start_time"]
        requests_per_second = (
            self._stats["total_requests"] / uptime if uptime > 0 else 0
        )

        return {
            "global_stats": {
                **self._stats,
                "uptime_seconds": uptime,
                "requests_per_second": requests_per_second,
                "block_rate": (
                    self._stats["blocked_requests"]
                    / self._stats["total_requests"]
                    if self._stats["total_requests"] > 0
                    else 0
                ),
            },
            "backend_stats": backend_stats,
            "configured_keys": len(self._per_key_configs),
        }


class RateLimitMiddleware:
    """Middleware for applying rate limiting to web requests."""

    def __init__(
        self,
        rate_limiter: RateLimiter,
        get_client_ip: Optional[callable] = None,
        get_user_id: Optional[callable] = None,
        get_endpoint: Optional[callable] = None,
    ):
        self.rate_limiter = rate_limiter
        self.get_client_ip = get_client_ip or self._default_get_client_ip
        self.get_user_id = get_user_id or self._default_get_user_id
        self.get_endpoint = get_endpoint or self._default_get_endpoint

    def _default_get_client_ip(self, request) -> str:
        """Default client IP extraction."""
        return getattr(request, "client", {}).get("host", "127.0.0.1")

    def _default_get_user_id(self, request) -> Optional[str]:
        """Default user ID extraction."""
        return None  # Override in subclasses

    def _default_get_endpoint(self, request) -> str:
        """Default endpoint extraction."""
        return getattr(request, "url", {}).path or "/"

    async def __call__(self, request, call_next):
        """Apply rate limiting to request."""
        client_ip = self.get_client_ip(request)
        user_id = self.get_user_id(request)
        endpoint = self.get_endpoint(request)

        key = self.rate_limiter.get_key_for_request(
            client_ip, user_id, endpoint
        )
        result = await self.rate_limiter.check_rate_limit(key)

        if not result.allowed:
            # Return rate limit exceeded response
            return self._create_rate_limit_response(result)

        # Add rate limit headers to response
        response = await call_next(request)
        self._add_rate_limit_headers(response, result)

        return response

    def _create_rate_limit_response(self, result: RateLimitResult):
        """Create rate limit exceeded response."""
        # This should be implemented based on your web framework
        # For now, return a generic response structure
        return {
            "status_code": 429,
            "headers": {
                "X-RateLimit-Remaining": str(result.remaining),
                "X-RateLimit-Reset": str(int(result.reset_time)),
                "Retry-After": str(int(result.retry_after))
                if result.retry_after
                else "60",
            },
            "body": {
                "error": "Rate limit exceeded",
                "retry_after": result.retry_after,
            },
        }

    def _add_rate_limit_headers(self, response, result: RateLimitResult):
        """Add rate limit headers to response."""
        if hasattr(response, "headers"):
            response.headers["X-RateLimit-Remaining"] = str(result.remaining)
            response.headers["X-RateLimit-Reset"] = str(int(result.reset_time))
