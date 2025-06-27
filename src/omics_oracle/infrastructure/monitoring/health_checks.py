"""
Health Check System

Comprehensive health check system for monitoring application health:
- Component-level health checks
- Dependency health monitoring
- Readiness and liveness probes
- Health check aggregation and reporting
"""

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

import aiohttp

logger = logging.getLogger(__name__)


class HealthStatus(Enum):
    """Health check status enumeration."""

    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


@dataclass
class HealthCheckResult:
    """Result of a health check."""

    name: str
    status: HealthStatus
    message: str
    timestamp: float
    duration_ms: float
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "name": self.name,
            "status": self.status.value,
            "message": self.message,
            "timestamp": self.timestamp,
            "duration_ms": self.duration_ms,
            "metadata": self.metadata,
        }


class HealthCheck(ABC):
    """Abstract base class for health checks."""

    def __init__(self, name: str, timeout_seconds: float = 30.0):
        self.name = name
        self.timeout_seconds = timeout_seconds

    @abstractmethod
    async def check(self) -> HealthCheckResult:
        """Perform the health check."""
        pass

    async def safe_check(self) -> HealthCheckResult:
        """Perform health check with timeout and error handling."""
        start_time = time.time()

        try:
            result = await asyncio.wait_for(
                self.check(), timeout=self.timeout_seconds
            )
            return result

        except asyncio.TimeoutError:
            duration_ms = (time.time() - start_time) * 1000
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.UNHEALTHY,
                message=f"Health check timed out after {self.timeout_seconds}s",
                timestamp=time.time(),
                duration_ms=duration_ms,
            )

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.UNHEALTHY,
                message=f"Health check failed: {str(e)}",
                timestamp=time.time(),
                duration_ms=duration_ms,
                metadata={"error_type": type(e).__name__},
            )


class DatabaseHealthCheck(HealthCheck):
    """Health check for database connectivity."""

    def __init__(self, connection_string: str, timeout_seconds: float = 10.0):
        super().__init__("database", timeout_seconds)
        self.connection_string = connection_string

    async def check(self) -> HealthCheckResult:
        """Check database health."""
        start_time = time.time()

        try:
            # This would be implemented based on your database type
            # For now, simulate a database check
            await asyncio.sleep(0.01)  # Simulate DB query

            duration_ms = (time.time() - start_time) * 1000
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.HEALTHY,
                message="Database connection successful",
                timestamp=time.time(),
                duration_ms=duration_ms,
                metadata={"connection_pool_size": 10},  # Example metadata
            )

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.UNHEALTHY,
                message=f"Database connection failed: {str(e)}",
                timestamp=time.time(),
                duration_ms=duration_ms,
            )


class ExternalApiHealthCheck(HealthCheck):
    """Health check for external API endpoints."""

    def __init__(self, name: str, url: str, timeout_seconds: float = 10.0):
        super().__init__(name, timeout_seconds)
        self.url = url

    async def check(self) -> HealthCheckResult:
        """Check external API health."""
        start_time = time.time()

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout_seconds),
                ) as response:
                    duration_ms = (time.time() - start_time) * 1000

                    if response.status < 400:
                        return HealthCheckResult(
                            name=self.name,
                            status=HealthStatus.HEALTHY,
                            message=f"API responded with status {response.status}",
                            timestamp=time.time(),
                            duration_ms=duration_ms,
                            metadata={
                                "status_code": response.status,
                                "response_headers": dict(response.headers),
                            },
                        )
                    else:
                        return HealthCheckResult(
                            name=self.name,
                            status=HealthStatus.UNHEALTHY,
                            message=f"API responded with error status {response.status}",
                            timestamp=time.time(),
                            duration_ms=duration_ms,
                            metadata={"status_code": response.status},
                        )

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.UNHEALTHY,
                message=f"API check failed: {str(e)}",
                timestamp=time.time(),
                duration_ms=duration_ms,
            )


class MemoryHealthCheck(HealthCheck):
    """Health check for memory usage."""

    def __init__(self, max_memory_percent: float = 90.0):
        super().__init__("memory")
        self.max_memory_percent = max_memory_percent

    async def check(self) -> HealthCheckResult:
        """Check memory usage."""
        start_time = time.time()

        try:
            import psutil

            memory = psutil.virtual_memory()
            memory_percent = memory.percent

            duration_ms = (time.time() - start_time) * 1000

            if memory_percent < self.max_memory_percent:
                status = HealthStatus.HEALTHY
                message = f"Memory usage is {memory_percent:.1f}%"
            elif memory_percent < 95.0:
                status = HealthStatus.DEGRADED
                message = f"Memory usage is high: {memory_percent:.1f}%"
            else:
                status = HealthStatus.UNHEALTHY
                message = f"Memory usage is critical: {memory_percent:.1f}%"

            return HealthCheckResult(
                name=self.name,
                status=status,
                message=message,
                timestamp=time.time(),
                duration_ms=duration_ms,
                metadata={
                    "memory_percent": memory_percent,
                    "memory_available": memory.available,
                    "memory_total": memory.total,
                },
            )

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.UNKNOWN,
                message=f"Memory check failed: {str(e)}",
                timestamp=time.time(),
                duration_ms=duration_ms,
            )


class DiskHealthCheck(HealthCheck):
    """Health check for disk usage."""

    def __init__(self, path: str = "/", max_disk_percent: float = 85.0):
        super().__init__("disk")
        self.path = path
        self.max_disk_percent = max_disk_percent

    async def check(self) -> HealthCheckResult:
        """Check disk usage."""
        start_time = time.time()

        try:
            import psutil

            disk = psutil.disk_usage(self.path)
            disk_percent = (disk.used / disk.total) * 100

            duration_ms = (time.time() - start_time) * 1000

            if disk_percent < self.max_disk_percent:
                status = HealthStatus.HEALTHY
                message = f"Disk usage is {disk_percent:.1f}%"
            elif disk_percent < 95.0:
                status = HealthStatus.DEGRADED
                message = f"Disk usage is high: {disk_percent:.1f}%"
            else:
                status = HealthStatus.UNHEALTHY
                message = f"Disk usage is critical: {disk_percent:.1f}%"

            return HealthCheckResult(
                name=self.name,
                status=status,
                message=message,
                timestamp=time.time(),
                duration_ms=duration_ms,
                metadata={
                    "disk_percent": disk_percent,
                    "disk_free": disk.free,
                    "disk_total": disk.total,
                    "path": self.path,
                },
            )

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.UNKNOWN,
                message=f"Disk check failed: {str(e)}",
                timestamp=time.time(),
                duration_ms=duration_ms,
            )


class CustomHealthCheck(HealthCheck):
    """Custom health check with user-defined function."""

    def __init__(
        self,
        name: str,
        check_function: Callable[[], Any],
        timeout_seconds: float = 30.0,
    ):
        super().__init__(name, timeout_seconds)
        self.check_function = check_function

    async def check(self) -> HealthCheckResult:
        """Run custom health check function."""
        start_time = time.time()

        try:
            if asyncio.iscoroutinefunction(self.check_function):
                result = await self.check_function()
            else:
                result = self.check_function()

            duration_ms = (time.time() - start_time) * 1000

            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.HEALTHY,
                message="Custom health check passed",
                timestamp=time.time(),
                duration_ms=duration_ms,
                metadata={"result": str(result) if result else None},
            )

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return HealthCheckResult(
                name=self.name,
                status=HealthStatus.UNHEALTHY,
                message=f"Custom health check failed: {str(e)}",
                timestamp=time.time(),
                duration_ms=duration_ms,
            )


class HealthCheckManager:
    """Manager for coordinating multiple health checks."""

    def __init__(self):
        self._health_checks: Dict[str, HealthCheck] = {}
        self._last_results: Dict[str, HealthCheckResult] = {}
        self._check_intervals: Dict[str, float] = {}
        self._background_tasks: Dict[str, asyncio.Task] = {}

    def register_health_check(
        self,
        health_check: HealthCheck,
        interval_seconds: Optional[float] = None,
    ) -> None:
        """Register a health check."""
        self._health_checks[health_check.name] = health_check

        if interval_seconds:
            self._check_intervals[health_check.name] = interval_seconds

        logger.info(f"Registered health check: {health_check.name}")

    def unregister_health_check(self, name: str) -> None:
        """Unregister a health check."""
        if name in self._health_checks:
            del self._health_checks[name]

        if name in self._last_results:
            del self._last_results[name]

        if name in self._check_intervals:
            del self._check_intervals[name]

        if name in self._background_tasks:
            self._background_tasks[name].cancel()
            del self._background_tasks[name]

        logger.info(f"Unregistered health check: {name}")

    async def check_health(
        self, check_name: Optional[str] = None
    ) -> Dict[str, HealthCheckResult]:
        """Run health checks."""
        if check_name:
            if check_name not in self._health_checks:
                raise ValueError(f"Health check '{check_name}' not found")
            checks_to_run = {check_name: self._health_checks[check_name]}
        else:
            checks_to_run = self._health_checks

        results = {}

        # Run checks concurrently
        tasks = []
        for name, health_check in checks_to_run.items():
            task = asyncio.create_task(health_check.safe_check())
            tasks.append((name, task))

        # Collect results
        for name, task in tasks:
            try:
                result = await task
                results[name] = result
                self._last_results[name] = result
            except Exception as e:
                logger.error(f"Health check {name} failed unexpectedly: {e}")
                results[name] = HealthCheckResult(
                    name=name,
                    status=HealthStatus.UNKNOWN,
                    message=f"Unexpected error: {str(e)}",
                    timestamp=time.time(),
                    duration_ms=0,
                )

        return results

    async def get_overall_health(self) -> Dict[str, Any]:
        """Get overall system health summary."""
        health_results = await self.check_health()

        healthy_count = 0
        unhealthy_count = 0
        degraded_count = 0
        unknown_count = 0

        for result in health_results.values():
            if result.status == HealthStatus.HEALTHY:
                healthy_count += 1
            elif result.status == HealthStatus.UNHEALTHY:
                unhealthy_count += 1
            elif result.status == HealthStatus.DEGRADED:
                degraded_count += 1
            else:
                unknown_count += 1

        total_checks = len(health_results)

        # Determine overall status
        if unhealthy_count > 0:
            overall_status = HealthStatus.UNHEALTHY
        elif degraded_count > 0:
            overall_status = HealthStatus.DEGRADED
        elif unknown_count > 0:
            overall_status = HealthStatus.UNKNOWN
        else:
            overall_status = HealthStatus.HEALTHY

        return {
            "overall_status": overall_status.value,
            "total_checks": total_checks,
            "healthy": healthy_count,
            "unhealthy": unhealthy_count,
            "degraded": degraded_count,
            "unknown": unknown_count,
            "checks": {
                name: result.to_dict()
                for name, result in health_results.items()
            },
            "timestamp": time.time(),
        }

    def start_background_monitoring(self) -> None:
        """Start background health check monitoring."""
        for name, interval in self._check_intervals.items():
            if name not in self._background_tasks:
                task = asyncio.create_task(
                    self._background_health_check(name, interval)
                )
                self._background_tasks[name] = task
                logger.info(
                    f"Started background monitoring for {name} (interval: {interval}s)"
                )

    def stop_background_monitoring(self) -> None:
        """Stop background health check monitoring."""
        for name, task in self._background_tasks.items():
            task.cancel()
            logger.info(f"Stopped background monitoring for {name}")
        self._background_tasks.clear()

    async def _background_health_check(
        self, check_name: str, interval: float
    ) -> None:
        """Background task for periodic health checks."""
        while True:
            try:
                await asyncio.sleep(interval)
                result = await self.check_health(check_name)
                logger.debug(
                    f"Background health check {check_name}: {result[check_name].status.value}"
                )
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(
                    f"Background health check {check_name} failed: {e}"
                )
                await asyncio.sleep(
                    min(interval, 60)
                )  # Don't retry too quickly
