"""
Performance Monitoring Components

Provides comprehensive performance monitoring including:
- Request/response timing
- Memory usage tracking
- Database query performance
- Custom metrics collection
"""

import asyncio
import gc
import logging
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

import psutil

logger = logging.getLogger(__name__)


@dataclass
class PerformanceMetric:
    """Individual performance metric."""

    name: str
    value: float
    timestamp: float = field(default_factory=time.time)
    tags: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert metric to dictionary."""
        return {
            "name": self.name,
            "value": self.value,
            "timestamp": self.timestamp,
            "tags": self.tags,
        }


class PerformanceMonitor:
    """Comprehensive performance monitoring system."""

    def __init__(self, max_metrics: int = 10000):
        self.max_metrics = max_metrics
        self._metrics: deque = deque(maxlen=max_metrics)
        self._metric_counts: Dict[str, int] = defaultdict(int)
        self._metric_sums: Dict[str, float] = defaultdict(float)
        self._metric_mins: Dict[str, float] = defaultdict(lambda: float("inf"))
        self._metric_maxs: Dict[str, float] = defaultdict(float)
        self._start_time = time.time()
        self._process = psutil.Process()

    def record_metric(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None:
        """Record a performance metric."""
        metric = PerformanceMetric(name, value, tags=tags or {})
        self._metrics.append(metric)

        # Update aggregated statistics
        self._metric_counts[name] += 1
        self._metric_sums[name] += value
        self._metric_mins[name] = min(self._metric_mins[name], value)
        self._metric_maxs[name] = max(self._metric_maxs[name], value)

    @asynccontextmanager
    async def timer(self, metric_name: str, tags: Optional[Dict[str, str]] = None):
        """Context manager for timing operations."""
        start_time = time.time()
        try:
            yield
        finally:
            duration = time.time() - start_time
            self.record_metric(f"{metric_name}_duration", duration, tags)

    def record_request_metrics(self, endpoint: str, method: str, status_code: int, duration: float):
        """Record HTTP request metrics."""
        tags = {
            "endpoint": endpoint,
            "method": method,
            "status_code": str(status_code),
        }

        self.record_metric("http_request_duration", duration, tags)
        self.record_metric("http_request_count", 1, tags)

        # Record error rate
        if status_code >= 400:
            self.record_metric("http_request_errors", 1, tags)

    def record_database_metrics(self, query_type: str, table: str, duration: float):
        """Record database query metrics."""
        tags = {
            "query_type": query_type,
            "table": table,
        }

        self.record_metric("db_query_duration", duration, tags)
        self.record_metric("db_query_count", 1, tags)

    def record_memory_metrics(self) -> None:
        """Record current memory usage metrics."""
        memory_info = self._process.memory_info()

        self.record_metric("memory_rss", memory_info.rss)
        self.record_metric("memory_vms", memory_info.vms)
        self.record_metric("memory_percent", self._process.memory_percent())

        # Python GC stats
        gc_stats = gc.get_stats()
        for i, stats in enumerate(gc_stats):
            self.record_metric(f"gc_generation_{i}_collections", stats["collections"])
            self.record_metric(f"gc_generation_{i}_collected", stats["collected"])
            self.record_metric(f"gc_generation_{i}_uncollectable", stats["uncollectable"])

    def record_cpu_metrics(self) -> None:
        """Record CPU usage metrics."""
        cpu_percent = self._process.cpu_percent()
        cpu_times = self._process.cpu_times()

        self.record_metric("cpu_percent", cpu_percent)
        self.record_metric("cpu_user_time", cpu_times.user)
        self.record_metric("cpu_system_time", cpu_times.system)

    async def record_system_metrics(self) -> None:
        """Record comprehensive system metrics."""
        self.record_memory_metrics()
        self.record_cpu_metrics()

        # System-wide metrics
        system_cpu = psutil.cpu_percent(interval=0.1)
        system_memory = psutil.virtual_memory()

        self.record_metric("system_cpu_percent", system_cpu)
        self.record_metric("system_memory_percent", system_memory.percent)
        self.record_metric("system_memory_available", system_memory.available)

    def get_metric_summary(self, metric_name: str) -> Dict[str, Any]:
        """Get statistical summary for a specific metric."""
        count = self._metric_counts.get(metric_name, 0)
        if count == 0:
            return {"count": 0}

        total = self._metric_sums[metric_name]
        minimum = self._metric_mins[metric_name]
        maximum = self._metric_maxs[metric_name]
        average = total / count

        return {
            "count": count,
            "sum": total,
            "min": minimum,
            "max": maximum,
            "avg": average,
        }

    def get_all_metrics(self) -> List[Dict[str, Any]]:
        """Get all recorded metrics."""
        return [metric.to_dict() for metric in self._metrics]

    def get_metrics_by_name(self, metric_name: str) -> List[Dict[str, Any]]:
        """Get all metrics with a specific name."""
        return [metric.to_dict() for metric in self._metrics if metric.name == metric_name]

    def get_recent_metrics(self, seconds: int = 60) -> List[Dict[str, Any]]:
        """Get metrics from the last N seconds."""
        cutoff_time = time.time() - seconds
        return [metric.to_dict() for metric in self._metrics if metric.timestamp >= cutoff_time]

    def get_summary_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance summary."""
        uptime = time.time() - self._start_time

        # Get summaries for key metrics
        summaries = {}
        for metric_name in self._metric_counts.keys():
            summaries[metric_name] = self.get_metric_summary(metric_name)

        return {
            "uptime_seconds": uptime,
            "total_metrics_recorded": len(self._metrics),
            "unique_metric_names": len(self._metric_counts),
            "metric_summaries": summaries,
            "system_info": {
                "cpu_count": psutil.cpu_count(),
                "memory_total": psutil.virtual_memory().total,
                "process_pid": self._process.pid,
            },
        }

    def clear_metrics(self) -> None:
        """Clear all recorded metrics."""
        self._metrics.clear()
        self._metric_counts.clear()
        self._metric_sums.clear()
        self._metric_mins.clear()
        self._metric_maxs.clear()
        logger.info("Performance metrics cleared")


class PerformanceDecorator:
    """Decorator for automatic performance monitoring."""

    def __init__(self, monitor: PerformanceMonitor):
        self.monitor = monitor

    def track_function(
        self,
        metric_name: Optional[str] = None,
        tags: Optional[Dict[str, str]] = None,
    ):
        """Decorator to track function execution time."""

        def decorator(func: Callable) -> Callable:
            name = metric_name or f"function_{func.__name__}"

            if asyncio.iscoroutinefunction(func):

                async def async_wrapper(*args, **kwargs):
                    async with self.monitor.timer(name, tags):
                        return await func(*args, **kwargs)

                return async_wrapper
            else:

                def sync_wrapper(*args, **kwargs):
                    start_time = time.time()
                    try:
                        result = func(*args, **kwargs)
                        duration = time.time() - start_time
                        self.monitor.record_metric(f"{name}_duration", duration, tags)
                        return result
                    except Exception as e:
                        duration = time.time() - start_time
                        error_tags = (tags or {}).copy()
                        error_tags["error"] = str(type(e).__name__)
                        self.monitor.record_metric(f"{name}_error", duration, error_tags)
                        raise

                return sync_wrapper

        return decorator

    def track_database_query(self, query_type: str, table: str):
        """Decorator to track database queries."""

        def decorator(func: Callable) -> Callable:
            if asyncio.iscoroutinefunction(func):

                async def async_wrapper(*args, **kwargs):
                    start_time = time.time()
                    try:
                        result = await func(*args, **kwargs)
                        duration = time.time() - start_time
                        self.monitor.record_database_metrics(query_type, table, duration)
                        return result
                    except Exception as e:
                        duration = time.time() - start_time
                        self.monitor.record_database_metrics(f"{query_type}_error", table, duration)
                        raise

                return async_wrapper
            else:

                def sync_wrapper(*args, **kwargs):
                    start_time = time.time()
                    try:
                        result = func(*args, **kwargs)
                        duration = time.time() - start_time
                        self.monitor.record_database_metrics(query_type, table, duration)
                        return result
                    except Exception as e:
                        duration = time.time() - start_time
                        self.monitor.record_database_metrics(f"{query_type}_error", table, duration)
                        raise

                return sync_wrapper

        return decorator


# Global performance monitor instance
performance_monitor = PerformanceMonitor()
perf_decorator = PerformanceDecorator(performance_monitor)
