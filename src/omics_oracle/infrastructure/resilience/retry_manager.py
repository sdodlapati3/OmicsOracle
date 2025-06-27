"""
Retry Management System

Provides intelligent retry logic with:
- Exponential backoff with jitter
- Custom retry conditions
- Multiple retry strategies
- Circuit breaker integration
"""

import asyncio
import logging
import random
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Optional, Type, Union

logger = logging.getLogger(__name__)


class RetryStrategy(Enum):
    """Retry strategy enumeration."""

    FIXED_DELAY = "fixed_delay"
    EXPONENTIAL_BACKOFF = "exponential_backoff"
    LINEAR_BACKOFF = "linear_backoff"


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""

    max_retries: int = 3
    base_delay_seconds: float = 1.0
    max_delay_seconds: float = 60.0
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL_BACKOFF
    jitter: bool = True
    retry_on_exceptions: tuple = (Exception,)
    backoff_multiplier: float = 2.0


@dataclass
class RetryResult:
    """Result of retry operation."""

    success: bool
    value: Any = None
    error: Optional[Exception] = None
    attempts: int = 0
    total_duration_seconds: float = 0.0
    last_delay_seconds: float = 0.0


class RetryCondition(ABC):
    """Abstract base class for retry conditions."""

    @abstractmethod
    def should_retry(self, exception: Exception, attempt: int) -> bool:
        """Determine if operation should be retried."""
        pass


class ExceptionTypeCondition(RetryCondition):
    """Retry condition based on exception type."""

    def __init__(self, exception_types: Union[Type[Exception], tuple]):
        if isinstance(exception_types, type):
            exception_types = (exception_types,)
        self.exception_types = exception_types

    def should_retry(self, exception: Exception, attempt: int) -> bool:
        """Check if exception type should trigger retry."""
        return isinstance(exception, self.exception_types)


class MaxAttemptsCondition(RetryCondition):
    """Retry condition based on maximum attempts."""

    def __init__(self, max_attempts: int):
        self.max_attempts = max_attempts

    def should_retry(self, exception: Exception, attempt: int) -> bool:
        """Check if maximum attempts reached."""
        return attempt < self.max_attempts


class CustomCondition(RetryCondition):
    """Custom retry condition with user-defined function."""

    def __init__(self, condition_func: Callable[[Exception, int], bool]):
        self.condition_func = condition_func

    def should_retry(self, exception: Exception, attempt: int) -> bool:
        """Use custom condition function."""
        return self.condition_func(exception, attempt)


class RetryManager:
    """Intelligent retry management system."""

    def __init__(self, config: Optional[RetryConfig] = None):
        self.config = config or RetryConfig()
        self._conditions: list[RetryCondition] = [
            ExceptionTypeCondition(self.config.retry_on_exceptions),
            MaxAttemptsCondition(self.config.max_retries),
        ]

    def add_condition(self, condition: RetryCondition) -> None:
        """Add custom retry condition."""
        self._conditions.append(condition)

    def _should_retry(self, exception: Exception, attempt: int) -> bool:
        """Check if operation should be retried based on all conditions."""
        return all(
            condition.should_retry(exception, attempt)
            for condition in self._conditions
        )

    def _calculate_delay(self, attempt: int) -> float:
        """Calculate delay for next retry attempt."""
        if self.config.strategy == RetryStrategy.FIXED_DELAY:
            delay = self.config.base_delay_seconds
        elif self.config.strategy == RetryStrategy.EXPONENTIAL_BACKOFF:
            delay = self.config.base_delay_seconds * (
                self.config.backoff_multiplier**attempt
            )
        elif self.config.strategy == RetryStrategy.LINEAR_BACKOFF:
            delay = self.config.base_delay_seconds * (attempt + 1)
        else:
            delay = self.config.base_delay_seconds

        # Apply maximum delay limit
        delay = min(delay, self.config.max_delay_seconds)

        # Add jitter if enabled
        if self.config.jitter:
            jitter_range = delay * 0.1  # 10% jitter
            delay += random.uniform(-jitter_range, jitter_range)

        return max(0, delay)

    async def retry_async(self, func: Callable, *args, **kwargs) -> RetryResult:
        """Execute async function with retry logic."""
        start_time = time.time()
        attempt = 0
        last_exception = None
        last_delay = 0.0

        while attempt <= self.config.max_retries:
            try:
                if asyncio.iscoroutinefunction(func):
                    result = await func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)

                total_duration = time.time() - start_time
                return RetryResult(
                    success=True,
                    value=result,
                    attempts=attempt + 1,
                    total_duration_seconds=total_duration,
                    last_delay_seconds=last_delay,
                )

            except Exception as e:
                last_exception = e
                attempt += 1

                if not self._should_retry(e, attempt):
                    break

                if attempt <= self.config.max_retries:
                    delay = self._calculate_delay(attempt - 1)
                    last_delay = delay
                    logger.warning(
                        f"Retry attempt {attempt} after {delay:.2f}s delay. Error: {e}"
                    )
                    await asyncio.sleep(delay)

        total_duration = time.time() - start_time
        return RetryResult(
            success=False,
            error=last_exception,
            attempts=attempt,
            total_duration_seconds=total_duration,
            last_delay_seconds=last_delay,
        )

    def retry_sync(self, func: Callable, *args, **kwargs) -> RetryResult:
        """Execute sync function with retry logic."""
        start_time = time.time()
        attempt = 0
        last_exception = None
        last_delay = 0.0

        while attempt <= self.config.max_retries:
            try:
                result = func(*args, **kwargs)
                total_duration = time.time() - start_time
                return RetryResult(
                    success=True,
                    value=result,
                    attempts=attempt + 1,
                    total_duration_seconds=total_duration,
                    last_delay_seconds=last_delay,
                )

            except Exception as e:
                last_exception = e
                attempt += 1

                if not self._should_retry(e, attempt):
                    break

                if attempt <= self.config.max_retries:
                    delay = self._calculate_delay(attempt - 1)
                    last_delay = delay
                    logger.warning(
                        f"Retry attempt {attempt} after {delay:.2f}s delay. Error: {e}"
                    )
                    time.sleep(delay)

        total_duration = time.time() - start_time
        return RetryResult(
            success=False,
            error=last_exception,
            attempts=attempt,
            total_duration_seconds=total_duration,
            last_delay_seconds=last_delay,
        )


class RetryDecorator:
    """Decorator for adding retry logic to functions."""

    def __init__(self, config: Optional[RetryConfig] = None):
        self.retry_manager = RetryManager(config)

    def __call__(self, func: Callable) -> Callable:
        """Apply retry logic to function."""
        if asyncio.iscoroutinefunction(func):

            async def async_wrapper(*args, **kwargs):
                result = await self.retry_manager.retry_async(
                    func, *args, **kwargs
                )
                if result.success:
                    return result.value
                else:
                    raise result.error

            return async_wrapper
        else:

            def sync_wrapper(*args, **kwargs):
                result = self.retry_manager.retry_sync(func, *args, **kwargs)
                if result.success:
                    return result.value
                else:
                    raise result.error

            return sync_wrapper


def retry(
    max_retries: int = 3,
    base_delay: float = 1.0,
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL_BACKOFF,
    retry_on: tuple = (Exception,),
) -> Callable:
    """Convenient retry decorator factory."""
    config = RetryConfig(
        max_retries=max_retries,
        base_delay_seconds=base_delay,
        strategy=strategy,
        retry_on_exceptions=retry_on,
    )
    return RetryDecorator(config)
