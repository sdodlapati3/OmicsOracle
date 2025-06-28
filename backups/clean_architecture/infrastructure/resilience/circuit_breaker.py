"""
Circuit Breaker Implementation

Provides circuit breaker pattern for resilient external service calls:
- Multiple circuit breaker states (closed, open, half-open)
- Configurable failure thresholds and timeouts
- Automatic recovery and testing
- Health monitoring and metrics
"""

import asyncio
import logging
import time
from collections import deque
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, Optional, Union

logger = logging.getLogger(__name__)


class CircuitBreakerState(Enum):
    """Circuit breaker state enumeration."""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing fast
    HALF_OPEN = "half_open"  # Testing recovery


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker."""

    failure_threshold: int = 5
    recovery_timeout_seconds: float = 60.0
    success_threshold: int = 3  # For half-open state
    timeout_seconds: float = 30.0
    window_size: int = 100  # Rolling window size
    min_requests: int = 10  # Minimum requests before opening


@dataclass
class CircuitBreakerResult:
    """Result of circuit breaker operation."""

    success: bool
    value: Any = None
    error: Optional[Exception] = None
    duration_ms: float = 0.0
    circuit_state: Optional[CircuitBreakerState] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class CircuitBreakerStats:
    """Statistics tracking for circuit breaker."""

    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self.results: deque = deque(maxlen=window_size)
        self.total_requests = 0
        self.total_failures = 0
        self.total_successes = 0
        self.state_changes = 0
        self.last_failure_time: Optional[float] = None
        self.last_success_time: Optional[float] = None

    def record_success(self) -> None:
        """Record a successful operation."""
        self.results.append(True)
        self.total_requests += 1
        self.total_successes += 1
        self.last_success_time = time.time()

    def record_failure(self) -> None:
        """Record a failed operation."""
        self.results.append(False)
        self.total_requests += 1
        self.total_failures += 1
        self.last_failure_time = time.time()

    def record_state_change(self) -> None:
        """Record a state change."""
        self.state_changes += 1

    @property
    def recent_failure_rate(self) -> float:
        """Calculate failure rate in recent window."""
        if not self.results:
            return 0.0
        failures = sum(1 for result in self.results if not result)
        return failures / len(self.results)

    @property
    def recent_success_rate(self) -> float:
        """Calculate success rate in recent window."""
        return 1.0 - self.recent_failure_rate

    @property
    def recent_request_count(self) -> int:
        """Get request count in recent window."""
        return len(self.results)

    @property
    def overall_failure_rate(self) -> float:
        """Calculate overall failure rate."""
        if self.total_requests == 0:
            return 0.0
        return self.total_failures / self.total_requests

    def to_dict(self) -> Dict[str, Any]:
        """Convert stats to dictionary."""
        return {
            "total_requests": self.total_requests,
            "total_successes": self.total_successes,
            "total_failures": self.total_failures,
            "overall_failure_rate": self.overall_failure_rate,
            "recent_failure_rate": self.recent_failure_rate,
            "recent_success_rate": self.recent_success_rate,
            "recent_request_count": self.recent_request_count,
            "state_changes": self.state_changes,
            "last_failure_time": self.last_failure_time,
            "last_success_time": self.last_success_time,
        }


class CircuitBreaker:
    """Circuit breaker implementation for resilient service calls."""

    def __init__(self, name: str, config: Optional[CircuitBreakerConfig] = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.state = CircuitBreakerState.CLOSED
        self.stats = CircuitBreakerStats(self.config.window_size)
        self.last_failure_time: Optional[float] = None
        self.half_open_successes = 0
        self._lock = asyncio.Lock()

    async def call(self, func: Callable, *args, **kwargs) -> CircuitBreakerResult:
        """Execute function with circuit breaker protection."""
        async with self._lock:
            # Check if circuit should remain open
            if self.state == CircuitBreakerState.OPEN:
                if self._should_attempt_reset():
                    self._transition_to_half_open()
                else:
                    return CircuitBreakerResult(
                        success=False,
                        error=CircuitBreakerOpenException(f"Circuit breaker {self.name} is OPEN"),
                        circuit_state=self.state,
                        metadata={"reason": "circuit_open"},
                    )

        # Execute the function
        start_time = time.time()
        try:
            if asyncio.iscoroutinefunction(func):
                result = await asyncio.wait_for(func(*args, **kwargs), timeout=self.config.timeout_seconds)
            else:
                result = func(*args, **kwargs)

            duration_ms = (time.time() - start_time) * 1000

            # Handle success
            await self._handle_success()

            return CircuitBreakerResult(
                success=True,
                value=result,
                duration_ms=duration_ms,
                circuit_state=self.state,
                metadata={"execution_time_ms": duration_ms},
            )

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000

            # Handle failure
            await self._handle_failure(e)

            return CircuitBreakerResult(
                success=False,
                error=e,
                duration_ms=duration_ms,
                circuit_state=self.state,
                metadata={
                    "execution_time_ms": duration_ms,
                    "error_type": type(e).__name__,
                },
            )

    async def _handle_success(self) -> None:
        """Handle successful operation."""
        async with self._lock:
            self.stats.record_success()

            if self.state == CircuitBreakerState.HALF_OPEN:
                self.half_open_successes += 1
                if self.half_open_successes >= self.config.success_threshold:
                    self._transition_to_closed()
            elif self.state == CircuitBreakerState.OPEN:
                # This shouldn't happen, but handle gracefully
                self._transition_to_half_open()

    async def _handle_failure(self, error: Exception) -> None:
        """Handle failed operation."""
        async with self._lock:
            self.stats.record_failure()
            self.last_failure_time = time.time()

            if self.state == CircuitBreakerState.CLOSED:
                if self._should_open_circuit():
                    self._transition_to_open()
            elif self.state == CircuitBreakerState.HALF_OPEN:
                self._transition_to_open()

    def _should_open_circuit(self) -> bool:
        """Check if circuit should be opened."""
        # Need minimum requests before considering opening
        if self.stats.recent_request_count < self.config.min_requests:
            return False

        # Check failure threshold
        recent_failures = sum(1 for result in self.stats.results if not result)

        return recent_failures >= self.config.failure_threshold

    def _should_attempt_reset(self) -> bool:
        """Check if circuit should attempt reset."""
        if self.last_failure_time is None:
            return True

        time_since_failure = time.time() - self.last_failure_time
        return time_since_failure >= self.config.recovery_timeout_seconds

    def _transition_to_closed(self) -> None:
        """Transition circuit to closed state."""
        logger.info(f"Circuit breaker {self.name} transitioning to CLOSED")
        self.state = CircuitBreakerState.CLOSED
        self.half_open_successes = 0
        self.stats.record_state_change()

    def _transition_to_open(self) -> None:
        """Transition circuit to open state."""
        logger.warning(f"Circuit breaker {self.name} transitioning to OPEN")
        self.state = CircuitBreakerState.OPEN
        self.half_open_successes = 0
        self.stats.record_state_change()

    def _transition_to_half_open(self) -> None:
        """Transition circuit to half-open state."""
        logger.info(f"Circuit breaker {self.name} transitioning to HALF_OPEN")
        self.state = CircuitBreakerState.HALF_OPEN
        self.half_open_successes = 0
        self.stats.record_state_change()

    async def force_open(self) -> None:
        """Manually force circuit to open state."""
        async with self._lock:
            self._transition_to_open()
            logger.warning(f"Circuit breaker {self.name} manually forced to OPEN")

    async def force_closed(self) -> None:
        """Manually force circuit to closed state."""
        async with self._lock:
            self._transition_to_closed()
            logger.info(f"Circuit breaker {self.name} manually forced to CLOSED")

    async def reset(self) -> None:
        """Reset circuit breaker statistics."""
        async with self._lock:
            self.state = CircuitBreakerState.CLOSED
            self.stats = CircuitBreakerStats(self.config.window_size)
            self.last_failure_time = None
            self.half_open_successes = 0
            logger.info(f"Circuit breaker {self.name} reset")

    def get_status(self) -> Dict[str, Any]:
        """Get current circuit breaker status."""
        return {
            "name": self.name,
            "state": self.state.value,
            "config": {
                "failure_threshold": self.config.failure_threshold,
                "recovery_timeout_seconds": self.config.recovery_timeout_seconds,
                "success_threshold": self.config.success_threshold,
                "timeout_seconds": self.config.timeout_seconds,
                "window_size": self.config.window_size,
                "min_requests": self.config.min_requests,
            },
            "stats": self.stats.to_dict(),
            "half_open_successes": self.half_open_successes,
            "last_failure_time": self.last_failure_time,
        }


class CircuitBreakerOpenException(Exception):
    """Exception raised when circuit breaker is open."""

    pass


class CircuitBreakerManager:
    """Manager for multiple circuit breakers."""

    def __init__(self):
        self._breakers: Dict[str, CircuitBreaker] = {}

    def get_or_create_breaker(
        self, name: str, config: Optional[CircuitBreakerConfig] = None
    ) -> CircuitBreaker:
        """Get existing or create new circuit breaker."""
        if name not in self._breakers:
            self._breakers[name] = CircuitBreaker(name, config)
            logger.info(f"Created circuit breaker: {name}")

        return self._breakers[name]

    async def call_with_breaker(
        self,
        breaker_name: str,
        func: Callable,
        *args,
        config: Optional[CircuitBreakerConfig] = None,
        **kwargs,
    ) -> CircuitBreakerResult:
        """Execute function with named circuit breaker."""
        breaker = self.get_or_create_breaker(breaker_name, config)
        return await breaker.call(func, *args, **kwargs)

    def get_breaker(self, name: str) -> Optional[CircuitBreaker]:
        """Get circuit breaker by name."""
        return self._breakers.get(name)

    def remove_breaker(self, name: str) -> bool:
        """Remove circuit breaker."""
        if name in self._breakers:
            del self._breakers[name]
            logger.info(f"Removed circuit breaker: {name}")
            return True
        return False

    async def reset_all_breakers(self) -> None:
        """Reset all circuit breakers."""
        for breaker in self._breakers.values():
            await breaker.reset()
        logger.info("Reset all circuit breakers")

    def get_all_status(self) -> Dict[str, Any]:
        """Get status of all circuit breakers."""
        return {name: breaker.get_status() for name, breaker in self._breakers.items()}

    def get_summary_stats(self) -> Dict[str, Any]:
        """Get summary statistics across all breakers."""
        if not self._breakers:
            return {
                "total_breakers": 0,
                "states": {},
                "total_requests": 0,
                "total_failures": 0,
            }

        states = {}
        total_requests = 0
        total_failures = 0

        for breaker in self._breakers.values():
            state = breaker.state.value
            states[state] = states.get(state, 0) + 1
            total_requests += breaker.stats.total_requests
            total_failures += breaker.stats.total_failures

        return {
            "total_breakers": len(self._breakers),
            "states": states,
            "total_requests": total_requests,
            "total_failures": total_failures,
            "overall_failure_rate": (total_failures / total_requests if total_requests > 0 else 0.0),
        }


# Global circuit breaker manager
circuit_breaker_manager = CircuitBreakerManager()
