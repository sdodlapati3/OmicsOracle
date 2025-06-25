"""
Performance monitoring and metrics collection for the futuristic interface
"""

import asyncio
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class PerformanceMetric:
    """Individual performance metric"""

    name: str
    value: float
    unit: str
    timestamp: datetime
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class RequestMetrics:
    """HTTP request performance metrics"""

    endpoint: str
    method: str
    status_code: int
    response_time_ms: float
    timestamp: datetime
    user_agent: Optional[str] = None
    ip_address: Optional[str] = None


class PerformanceTracker:
    """Track and aggregate performance metrics"""

    def __init__(self, max_history: int = 1000):
        self.max_history = max_history
        self.metrics_history: deque = deque(maxlen=max_history)
        self.request_history: deque = deque(maxlen=max_history)
        self.endpoint_stats = defaultdict(list)
        self.agent_stats = defaultdict(list)
        self.start_time = time.time()

    def record_metric(
        self,
        name: str,
        value: float,
        unit: str = "",
        tags: Dict[str, str] = None,
    ):
        """Record a performance metric"""
        metric = PerformanceMetric(
            name=name,
            value=value,
            unit=unit,
            timestamp=datetime.now(),
            tags=tags or {},
        )
        self.metrics_history.append(metric)

    def record_request(
        self,
        endpoint: str,
        method: str,
        status_code: int,
        response_time_ms: float,
        user_agent: str = None,
        ip_address: str = None,
    ):
        """Record HTTP request metrics"""
        request_metric = RequestMetrics(
            endpoint=endpoint,
            method=method,
            status_code=status_code,
            response_time_ms=response_time_ms,
            timestamp=datetime.now(),
            user_agent=user_agent,
            ip_address=ip_address,
        )
        self.request_history.append(request_metric)
        self.endpoint_stats[f"{method} {endpoint}"].append(response_time_ms)

    def record_agent_performance(
        self,
        agent_type: str,
        operation: str,
        execution_time_ms: float,
        success: bool,
    ):
        """Record agent performance metrics"""
        self.agent_stats[f"{agent_type}_{operation}"].append(
            {
                "execution_time_ms": execution_time_ms,
                "success": success,
                "timestamp": datetime.now(),
            }
        )

        # Also record as general metric
        self.record_metric(
            f"agent.{agent_type}.{operation}.time",
            execution_time_ms,
            "ms",
            {
                "agent_type": agent_type,
                "operation": operation,
                "success": str(success),
            },
        )

    def get_endpoint_stats(self, endpoint: str = None) -> Dict[str, Any]:
        """Get statistics for endpoints"""
        if endpoint:
            times = self.endpoint_stats.get(endpoint, [])
            if not times:
                return {"error": "No data for endpoint"}

            return {
                "endpoint": endpoint,
                "total_requests": len(times),
                "avg_response_time_ms": sum(times) / len(times),
                "min_response_time_ms": min(times),
                "max_response_time_ms": max(times),
                "p95_response_time_ms": self._percentile(times, 95),
                "p99_response_time_ms": self._percentile(times, 99),
            }
        else:
            # Return stats for all endpoints
            stats = {}
            for endpoint, times in self.endpoint_stats.items():
                if times:
                    stats[endpoint] = {
                        "total_requests": len(times),
                        "avg_response_time_ms": sum(times) / len(times),
                        "p95_response_time_ms": self._percentile(times, 95),
                    }
            return stats

    def get_agent_stats(self, agent_type: str = None) -> Dict[str, Any]:
        """Get agent performance statistics"""
        if agent_type:
            # Filter stats for specific agent type
            relevant_stats = {
                k: v
                for k, v in self.agent_stats.items()
                if k.startswith(agent_type)
            }
        else:
            relevant_stats = dict(self.agent_stats)

        results = {}
        for key, operations in relevant_stats.items():
            if operations:
                times = [op["execution_time_ms"] for op in operations]
                successes = [op["success"] for op in operations]

                results[key] = {
                    "total_operations": len(operations),
                    "success_rate": sum(successes) / len(successes) * 100,
                    "avg_execution_time_ms": sum(times) / len(times),
                    "min_execution_time_ms": min(times),
                    "max_execution_time_ms": max(times),
                    "p95_execution_time_ms": self._percentile(times, 95),
                }

        return results

    def get_system_metrics(self) -> Dict[str, Any]:
        """Get overall system performance metrics"""
        now = datetime.now()
        uptime_seconds = time.time() - self.start_time

        # Recent metrics (last 5 minutes)
        recent_cutoff = now - timedelta(minutes=5)
        recent_requests = [
            r for r in self.request_history if r.timestamp > recent_cutoff
        ]
        recent_metrics = [
            m for m in self.metrics_history if m.timestamp > recent_cutoff
        ]

        # Calculate request rates
        total_requests = len(self.request_history)
        recent_request_count = len(recent_requests)
        requests_per_minute = (
            (recent_request_count / 5) if recent_request_count > 0 else 0
        )

        # Calculate error rates
        recent_errors = [r for r in recent_requests if r.status_code >= 400]
        error_rate = (
            (len(recent_errors) / len(recent_requests) * 100)
            if recent_requests
            else 0
        )

        # Calculate response times
        if recent_requests:
            response_times = [r.response_time_ms for r in recent_requests]
            avg_response_time = sum(response_times) / len(response_times)
            p95_response_time = self._percentile(response_times, 95)
        else:
            avg_response_time = 0
            p95_response_time = 0

        return {
            "uptime_seconds": uptime_seconds,
            "total_requests": total_requests,
            "requests_per_minute": requests_per_minute,
            "error_rate_percent": error_rate,
            "avg_response_time_ms": avg_response_time,
            "p95_response_time_ms": p95_response_time,
            "active_endpoints": len(self.endpoint_stats),
            "metrics_collected": len(self.metrics_history),
            "timestamp": now,
        }

    def get_recent_slow_requests(
        self, threshold_ms: float = 1000, limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Get recent slow requests above threshold"""
        slow_requests = [
            {
                "endpoint": r.endpoint,
                "method": r.method,
                "response_time_ms": r.response_time_ms,
                "status_code": r.status_code,
                "timestamp": r.timestamp,
                "user_agent": r.user_agent,
            }
            for r in self.request_history
            if r.response_time_ms > threshold_ms
        ]

        # Sort by response time (slowest first) and limit
        slow_requests.sort(key=lambda x: x["response_time_ms"], reverse=True)
        return slow_requests[:limit]

    def _percentile(self, data: List[float], percentile: int) -> float:
        """Calculate percentile of a dataset"""
        if not data:
            return 0.0

        sorted_data = sorted(data)
        index = int((percentile / 100) * len(sorted_data))
        if index >= len(sorted_data):
            index = len(sorted_data) - 1
        return sorted_data[index]

    def reset_metrics(self):
        """Reset all collected metrics"""
        self.metrics_history.clear()
        self.request_history.clear()
        self.endpoint_stats.clear()
        self.agent_stats.clear()
        self.start_time = time.time()
        logger.info("Performance metrics reset")


# Global performance tracker
performance_tracker = PerformanceTracker()


class PerformanceMiddleware:
    """Middleware to automatically track request performance"""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        start_time = time.time()

        # Extract request info
        method = scope["method"]
        path = scope["path"]

        # Get client info
        client = scope.get("client", ["unknown", 0])
        ip_address = client[0] if client else "unknown"

        headers = dict(scope.get("headers", []))
        user_agent = headers.get(b"user-agent", b"").decode("utf-8")

        # Track the request
        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status_code = message["status"]
                response_time_ms = (time.time() - start_time) * 1000

                # Record the request metrics
                performance_tracker.record_request(
                    endpoint=path,
                    method=method,
                    status_code=status_code,
                    response_time_ms=response_time_ms,
                    user_agent=user_agent,
                    ip_address=ip_address,
                )

            await send(message)

        await self.app(scope, receive, send_wrapper)


def track_agent_performance(agent_type: str, operation: str):
    """Decorator to track agent performance"""

    def decorator(func):
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            success = False

            try:
                result = await func(*args, **kwargs)
                success = True
                return result
            except Exception as e:
                logger.error(f"Agent {agent_type}.{operation} failed: {e}")
                raise
            finally:
                execution_time_ms = (time.time() - start_time) * 1000
                performance_tracker.record_agent_performance(
                    agent_type, operation, execution_time_ms, success
                )

        return wrapper

    return decorator


def track_function_performance(name: str, tags: Dict[str, str] = None):
    """Decorator to track function performance"""

    def decorator(func):
        async def wrapper(*args, **kwargs):
            start_time = time.time()

            try:
                result = await func(*args, **kwargs)
                return result
            finally:
                execution_time_ms = (time.time() - start_time) * 1000
                performance_tracker.record_metric(
                    f"function.{name}.execution_time",
                    execution_time_ms,
                    "ms",
                    tags,
                )

        return wrapper

    return decorator
