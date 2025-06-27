"""
Connection Pool Implementation

Provides connection pooling for external APIs including NCBI.
Includes rate limiting, connection reuse, and timeout handling.
"""

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, AsyncGenerator, Dict, Optional
from urllib.parse import urlparse

import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector

logger = logging.getLogger(__name__)


@dataclass
class ConnectionConfig:
    """Configuration for connection pooling."""

    max_connections: int = 100
    max_connections_per_host: int = 30
    timeout_seconds: int = 30
    keepalive_timeout: int = 30
    enable_cleanup_closed: bool = True
    rate_limit_per_second: int = 10


class ConnectionPool:
    """High-performance connection pool for HTTP requests."""

    def __init__(self, config: Optional[ConnectionConfig] = None):
        self.config = config or ConnectionConfig()
        self._session: Optional[ClientSession] = None
        self._rate_limiter = RateLimiter(self.config.rate_limit_per_second)
        self._stats = ConnectionStats()

    async def __aenter__(self) -> "ConnectionPool":
        """Async context manager entry."""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

    async def start(self) -> None:
        """Initialize the connection pool."""
        if self._session is not None:
            return

        # Create TCP connector with optimized settings
        connector = TCPConnector(
            limit=self.config.max_connections,
            limit_per_host=self.config.max_connections_per_host,
            keepalive_timeout=self.config.keepalive_timeout,
            enable_cleanup_closed=self.config.enable_cleanup_closed,
            use_dns_cache=True,
            ttl_dns_cache=300,  # 5 minutes DNS cache
        )

        # Create client timeout
        timeout = ClientTimeout(total=self.config.timeout_seconds)

        # Create session with optimized settings
        self._session = ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                "User-Agent": "OmicsOracle/1.0",
                "Accept": "application/json, text/plain, */*",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
            },
        )

        logger.info(
            f"Connection pool started with {self.config.max_connections} max connections"
        )

    async def close(self) -> None:
        """Close the connection pool and cleanup resources."""
        if self._session:
            await self._session.close()
            self._session = None
            logger.info("Connection pool closed")

    @asynccontextmanager
    async def get_session(self) -> AsyncGenerator[ClientSession, None]:
        """Get a session from the pool with rate limiting."""
        if self._session is None:
            await self.start()

        # Apply rate limiting
        await self._rate_limiter.acquire()

        start_time = time.time()
        try:
            self._stats.record_request_start()
            yield self._session
            self._stats.record_request_success(time.time() - start_time)
        except Exception as e:
            self._stats.record_request_error(time.time() - start_time)
            logger.error(f"Request failed: {e}")
            raise

    async def get(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """Perform GET request with connection pooling."""
        async with self.get_session() as session:
            return await session.get(url, **kwargs)

    async def post(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        """Perform POST request with connection pooling."""
        async with self.get_session() as session:
            return await session.post(url, **kwargs)

    def get_stats(self) -> Dict[str, Any]:
        """Get connection pool statistics."""
        return self._stats.to_dict()


class AsyncConnectionPool:
    """Enhanced async connection pool with advanced features."""

    def __init__(self, config: Optional[ConnectionConfig] = None):
        self.config = config or ConnectionConfig()
        self._pools: Dict[str, ConnectionPool] = {}
        self._lock = asyncio.Lock()

    async def get_pool(self, base_url: str) -> ConnectionPool:
        """Get or create a connection pool for a specific base URL."""
        parsed = urlparse(base_url)
        pool_key = f"{parsed.scheme}://{parsed.netloc}"

        async with self._lock:
            if pool_key not in self._pools:
                self._pools[pool_key] = ConnectionPool(self.config)
                await self._pools[pool_key].start()
                logger.info(f"Created connection pool for {pool_key}")

        return self._pools[pool_key]

    async def close_all(self) -> None:
        """Close all connection pools."""
        async with self._lock:
            for pool in self._pools.values():
                await pool.close()
            self._pools.clear()
            logger.info("All connection pools closed")

    async def get_global_stats(self) -> Dict[str, Any]:
        """Get statistics for all connection pools."""
        stats = {}
        for pool_key, pool in self._pools.items():
            stats[pool_key] = pool.get_stats()
        return stats


class RateLimiter:
    """Token bucket rate limiter for connection pool."""

    def __init__(self, rate_per_second: int):
        self.rate = rate_per_second
        self.tokens = rate_per_second
        self.last_update = time.time()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Acquire a token for rate limiting."""
        async with self._lock:
            now = time.time()
            time_passed = now - self.last_update
            self.tokens = min(self.rate, self.tokens + time_passed * self.rate)
            self.last_update = now

            if self.tokens < 1:
                sleep_time = (1 - self.tokens) / self.rate
                await asyncio.sleep(sleep_time)
                self.tokens = 0
            else:
                self.tokens -= 1


@dataclass
class ConnectionStats:
    """Statistics tracking for connection pool."""

    requests_started: int = 0
    requests_completed: int = 0
    requests_failed: int = 0
    total_response_time: float = 0.0
    min_response_time: float = float("inf")
    max_response_time: float = 0.0

    def record_request_start(self) -> None:
        """Record a request start."""
        self.requests_started += 1

    def record_request_success(self, response_time: float) -> None:
        """Record a successful request."""
        self.requests_completed += 1
        self._update_response_time(response_time)

    def record_request_error(self, response_time: float) -> None:
        """Record a failed request."""
        self.requests_failed += 1
        self._update_response_time(response_time)

    def _update_response_time(self, response_time: float) -> None:
        """Update response time statistics."""
        self.total_response_time += response_time
        self.min_response_time = min(self.min_response_time, response_time)
        self.max_response_time = max(self.max_response_time, response_time)

    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        total = self.requests_completed + self.requests_failed
        return self.requests_completed / total if total > 0 else 0.0

    @property
    def average_response_time(self) -> float:
        """Calculate average response time."""
        total = self.requests_completed + self.requests_failed
        return self.total_response_time / total if total > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert stats to dictionary."""
        return {
            "requests_started": self.requests_started,
            "requests_completed": self.requests_completed,
            "requests_failed": self.requests_failed,
            "success_rate": self.success_rate,
            "average_response_time": self.average_response_time,
            "min_response_time": self.min_response_time
            if self.min_response_time != float("inf")
            else 0.0,
            "max_response_time": self.max_response_time,
        }
