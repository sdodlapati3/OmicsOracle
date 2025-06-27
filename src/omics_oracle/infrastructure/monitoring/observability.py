"""
Observability Manager

Centralized observability system that combines:
- Metrics collection
- Distributed tracing
- Health monitoring
- Alert management
"""

import logging
from typing import Any, Dict, List, Optional

from .alerts import AlertManager
from .health_checks import HealthCheckManager
from .metrics import MetricsCollector
from .tracing import TracingManager

logger = logging.getLogger(__name__)


class ObservabilityManager:
    """Centralized observability management system."""

    def __init__(self):
        self.health_manager = HealthCheckManager()
        self.metrics_collector = MetricsCollector()
        self.tracing_manager = TracingManager()
        self.alert_manager = AlertManager()

    async def get_system_overview(self) -> Dict[str, Any]:
        """Get comprehensive system overview."""
        # Get health status
        health_status = await self.health_manager.get_overall_health()

        # Get metrics summary
        metrics_summary = self.metrics_collector.get_metrics_summary()

        # Get tracing info
        all_spans = self.tracing_manager.get_all_spans()

        # Get alert counts
        open_alerts = len(self.alert_manager.get_alerts(status=None))

        return {
            "health": health_status,
            "metrics": {
                "total_metrics": metrics_summary["total_metrics"],
                "counters_count": len(metrics_summary["counters"]),
                "gauges_count": len(metrics_summary["gauges"]),
            },
            "tracing": {
                "total_spans": len(all_spans),
                "active_tracers": len(self.tracing_manager._tracers),
            },
            "alerts": {
                "total_alerts": open_alerts,
                "rules_count": len(self.alert_manager._rules),
            },
        }


# Global observability manager
observability_manager = ObservabilityManager()
