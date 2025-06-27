"""
Request Batching Implementation

Provides intelligent request batching for external APIs to:
- Reduce API call overhead
- Implement batch processing
- Optimize throughput while respecting rate limits
"""

import asyncio
import logging
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Callable, Dict, Generic, List, Optional, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")
R = TypeVar("R")


@dataclass
class BatchRequest(Generic[T]):
    """Individual request in a batch."""

    request_id: str
    data: T
    timestamp: float
    future: asyncio.Future
    tags: Dict[str, str]

    def __post_init__(self):
        if not self.future:
            self.future = asyncio.Future()


@dataclass
class BatchConfig:
    """Configuration for request batching."""

    max_batch_size: int = 50
    max_wait_time_seconds: float = 1.0
    max_requests_per_second: int = 10
    enable_adaptive_batching: bool = True
    min_batch_size: int = 1


class RequestBatcher(Generic[T, R]):
    """Intelligent request batcher with adaptive sizing."""

    def __init__(
        self,
        batch_processor: Callable[[List[T]], List[R]],
        config: Optional[BatchConfig] = None,
        batch_key_func: Optional[Callable[[T], str]] = None,
    ):
        self.batch_processor = batch_processor
        self.config = config or BatchConfig()
        self.batch_key_func = batch_key_func or (lambda x: "default")

        # Batch management
        self._batches: Dict[str, List[BatchRequest[T]]] = defaultdict(list)
        self._batch_timers: Dict[str, asyncio.Handle] = {}
        self._processing_lock = asyncio.Lock()

        # Performance tracking
        self._stats = BatchStats()

        # Rate limiting
        self._rate_limiter = TokenBucketRateLimiter(
            self.config.max_requests_per_second
        )

    async def submit_request(
        self,
        data: T,
        request_id: Optional[str] = None,
        tags: Optional[Dict[str, str]] = None,
    ) -> R:
        """Submit a request for batching."""
        if request_id is None:
            request_id = f"req_{time.time()}_{id(data)}"

        batch_key = self.batch_key_func(data)
        request = BatchRequest(
            request_id=request_id,
            data=data,
            timestamp=time.time(),
            future=asyncio.Future(),
            tags=tags or {},
        )

        async with self._processing_lock:
            # Add to appropriate batch
            self._batches[batch_key].append(request)
            batch_size = len(self._batches[batch_key])

            # Schedule batch processing if needed
            if batch_size >= self.config.max_batch_size:
                # Process immediately if batch is full
                await self._process_batch(batch_key)
            elif batch_key not in self._batch_timers:
                # Schedule timer for partial batch
                timer = asyncio.get_event_loop().call_later(
                    self.config.max_wait_time_seconds,
                    lambda: asyncio.create_task(
                        self._process_batch_by_timer(batch_key)
                    ),
                )
                self._batch_timers[batch_key] = timer

        # Wait for result
        try:
            result = await request.future
            self._stats.record_success(request.timestamp)
            return result
        except Exception as e:
            self._stats.record_error(request.timestamp)
            raise

    async def _process_batch(self, batch_key: str) -> None:
        """Process a batch of requests."""
        if batch_key not in self._batches or not self._batches[batch_key]:
            return

        # Extract batch
        batch = self._batches[batch_key]
        self._batches[batch_key] = []

        # Cancel timer if active
        if batch_key in self._batch_timers:
            self._batch_timers[batch_key].cancel()
            del self._batch_timers[batch_key]

        if not batch:
            return

        logger.debug(f"Processing batch {batch_key} with {len(batch)} requests")

        # Apply rate limiting
        await self._rate_limiter.acquire()

        # Track batch processing
        batch_start = time.time()

        try:
            # Extract data for processing
            batch_data = [req.data for req in batch]

            # Process the batch
            results = await self._safe_process_batch(batch_data)

            # Distribute results
            if len(results) != len(batch):
                error_msg = f"Batch processor returned {len(results)} results for {len(batch)} requests"
                logger.error(error_msg)
                for req in batch:
                    if not req.future.done():
                        req.future.set_exception(ValueError(error_msg))
            else:
                for req, result in zip(batch, results):
                    if not req.future.done():
                        req.future.set_result(result)

        except Exception as e:
            logger.error(f"Batch processing failed: {e}")
            for req in batch:
                if not req.future.done():
                    req.future.set_exception(e)

        finally:
            batch_duration = time.time() - batch_start
            self._stats.record_batch_processed(len(batch), batch_duration)

    async def _process_batch_by_timer(self, batch_key: str) -> None:
        """Process batch triggered by timer."""
        async with self._processing_lock:
            await self._process_batch(batch_key)

    async def _safe_process_batch(self, batch_data: List[T]) -> List[R]:
        """Safely process batch with timeout and error handling."""
        try:
            if asyncio.iscoroutinefunction(self.batch_processor):
                return await asyncio.wait_for(
                    self.batch_processor(batch_data),
                    timeout=30.0,  # 30 second timeout
                )
            else:
                # Run sync processor in thread pool
                loop = asyncio.get_event_loop()
                return await loop.run_in_executor(
                    None, self.batch_processor, batch_data
                )
        except asyncio.TimeoutError:
            logger.error("Batch processing timed out")
            raise
        except Exception as e:
            logger.error(f"Batch processing error: {e}")
            raise

    async def flush_all_batches(self) -> None:
        """Force process all pending batches."""
        async with self._processing_lock:
            batch_keys = list(self._batches.keys())
            for batch_key in batch_keys:
                if self._batches[batch_key]:
                    await self._process_batch(batch_key)

    def get_stats(self) -> Dict[str, Any]:
        """Get batching statistics."""
        return self._stats.to_dict()

    async def close(self) -> None:
        """Clean shutdown of the batcher."""
        # Cancel all timers
        for timer in self._batch_timers.values():
            timer.cancel()
        self._batch_timers.clear()

        # Process remaining batches
        await self.flush_all_batches()

        logger.info("Request batcher closed")


class TokenBucketRateLimiter:
    """Token bucket implementation for rate limiting."""

    def __init__(self, rate_per_second: float):
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
class BatchStats:
    """Statistics for batch processing."""

    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_batches: int = 0
    total_batch_processing_time: float = 0.0
    min_batch_size: int = float("inf")
    max_batch_size: int = 0
    total_response_time: float = 0.0

    def record_success(self, request_timestamp: float) -> None:
        """Record a successful request."""
        self.total_requests += 1
        self.successful_requests += 1
        self.total_response_time += time.time() - request_timestamp

    def record_error(self, request_timestamp: float) -> None:
        """Record a failed request."""
        self.total_requests += 1
        self.failed_requests += 1
        self.total_response_time += time.time() - request_timestamp

    def record_batch_processed(
        self, batch_size: int, processing_time: float
    ) -> None:
        """Record batch processing metrics."""
        self.total_batches += 1
        self.total_batch_processing_time += processing_time
        self.min_batch_size = min(self.min_batch_size, batch_size)
        self.max_batch_size = max(self.max_batch_size, batch_size)

    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        return (
            self.successful_requests / self.total_requests
            if self.total_requests > 0
            else 0.0
        )

    @property
    def average_response_time(self) -> float:
        """Calculate average response time."""
        return (
            self.total_response_time / self.total_requests
            if self.total_requests > 0
            else 0.0
        )

    @property
    def average_batch_size(self) -> float:
        """Calculate average batch size."""
        return (
            self.total_requests / self.total_batches
            if self.total_batches > 0
            else 0.0
        )

    @property
    def average_batch_processing_time(self) -> float:
        """Calculate average batch processing time."""
        return (
            self.total_batch_processing_time / self.total_batches
            if self.total_batches > 0
            else 0.0
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert stats to dictionary."""
        return {
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "success_rate": self.success_rate,
            "total_batches": self.total_batches,
            "average_batch_size": self.average_batch_size,
            "min_batch_size": self.min_batch_size
            if self.min_batch_size != float("inf")
            else 0,
            "max_batch_size": self.max_batch_size,
            "average_response_time": self.average_response_time,
            "average_batch_processing_time": self.average_batch_processing_time,
        }
