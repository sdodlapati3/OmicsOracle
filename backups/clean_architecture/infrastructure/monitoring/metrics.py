"""
Metrics Collection System

Provides comprehensive metrics collection and aggregation:
- Custom metrics with tags and metadata
- System metrics (CPU, memory, disk)
- Application metrics (requests, errors, latency)
- Metrics export and aggregation
"""

import logging
import time
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


class MetricType(Enum):
    """Types of metrics that can be collected."""

    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


@dataclass
class Metric:
    """Individual metric data point."""

    name: str
    value: Union[int, float]
    metric_type: MetricType
    timestamp: float = field(default_factory=time.time)
    tags: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert metric to dictionary."""
        return {
            "name": self.name,
            "value": self.value,
            "type": self.metric_type.value,
            "timestamp": self.timestamp,
            "tags": self.tags,
        }


class MetricsCollector:
    """Comprehensive metrics collection system."""

    def __init__(self, max_metrics: int = 10000):
        self.max_metrics = max_metrics
        self._metrics: deque = deque(maxlen=max_metrics)
        self._counters: Dict[str, float] = defaultdict(float)
        self._gauges: Dict[str, float] = defaultdict(float)
        self._histograms: Dict[str, List[float]] = defaultdict(list)
        self._timers: Dict[str, List[float]] = defaultdict(list)

    def increment_counter(
        self,
        name: str,
        value: float = 1.0,
        tags: Optional[Dict[str, str]] = None,
    ) -> None:
        """Increment a counter metric."""
        self._counters[name] += value
        metric = Metric(name, value, MetricType.COUNTER, tags=tags or {})
        self._metrics.append(metric)

    def set_gauge(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None:
        """Set a gauge metric value."""
        self._gauges[name] = value
        metric = Metric(name, value, MetricType.GAUGE, tags=tags or {})
        self._metrics.append(metric)

    def record_histogram(self, name: str, value: float, tags: Optional[Dict[str, str]] = None) -> None:
        """Record a histogram value."""
        self._histograms[name].append(value)
        metric = Metric(name, value, MetricType.HISTOGRAM, tags=tags or {})
        self._metrics.append(metric)

    def record_timer(
        self,
        name: str,
        duration_ms: float,
        tags: Optional[Dict[str, str]] = None,
    ) -> None:
        """Record a timer value."""
        self._timers[name].append(duration_ms)
        metric = Metric(name, duration_ms, MetricType.TIMER, tags=tags or {})
        self._metrics.append(metric)

    def get_counter(self, name: str) -> float:
        """Get current counter value."""
        return self._counters.get(name, 0.0)

    def get_gauge(self, name: str) -> float:
        """Get current gauge value."""
        return self._gauges.get(name, 0.0)

    def get_histogram_stats(self, name: str) -> Dict[str, float]:
        """Get histogram statistics."""
        values = self._histograms.get(name, [])
        if not values:
            return {"count": 0}

        sorted_values = sorted(values)
        count = len(values)

        return {
            "count": count,
            "min": min(values),
            "max": max(values),
            "mean": sum(values) / count,
            "p50": sorted_values[int(count * 0.5)],
            "p95": sorted_values[int(count * 0.95)],
            "p99": sorted_values[int(count * 0.99)],
        }

    def get_timer_stats(self, name: str) -> Dict[str, float]:
        """Get timer statistics."""
        return self.get_histogram_stats(name)  # Timers are histograms

    def get_all_metrics(self) -> List[Dict[str, Any]]:
        """Get all collected metrics."""
        return [metric.to_dict() for metric in self._metrics]

    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get comprehensive metrics summary."""
        summary = {
            "total_metrics": len(self._metrics),
            "counters": dict(self._counters),
            "gauges": dict(self._gauges),
            "histograms": {},
            "timers": {},
        }

        for name in self._histograms:
            summary["histograms"][name] = self.get_histogram_stats(name)

        for name in self._timers:
            summary["timers"][name] = self.get_timer_stats(name)

        return summary

    def clear_metrics(self) -> None:
        """Clear all collected metrics."""
        self._metrics.clear()
        self._counters.clear()
        self._gauges.clear()
        self._histograms.clear()
        self._timers.clear()
        logger.info("All metrics cleared")


# Global metrics collector instance
metrics_collector = MetricsCollector()
