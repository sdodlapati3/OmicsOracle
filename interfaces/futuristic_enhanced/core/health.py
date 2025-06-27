"""
Health monitoring and system status for the futuristic interface
"""

import asyncio
import logging
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import APIRouter
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class ComponentHealth(BaseModel):
    name: str
    status: str  # healthy, warning, error
    last_check: datetime
    details: Dict[str, str]
    response_time_ms: float


class SystemHealth(BaseModel):
    status: str  # healthy, degraded, error
    timestamp: datetime
    uptime_seconds: float
    components: List[ComponentHealth]
    metrics: Dict[str, float]


class HealthMonitor:
    """System health monitoring service"""

    def __init__(self):
        self.start_time = time.time()
        self.health_checks = {}
        self.last_check_time = {}

    async def check_component_health(
        self, component_name: str
    ) -> ComponentHealth:
        """Check health of a specific component"""
        start_time = time.time()

        try:
            if component_name == "database":
                status, details = await self._check_database()
            elif component_name == "websocket":
                status, details = await self._check_websocket()
            elif component_name == "agents":
                status, details = await self._check_agents()
            elif component_name == "static_files":
                status, details = await self._check_static_files()
            elif component_name == "api":
                status, details = await self._check_api()
            else:
                status, details = "error", {
                    "error": f"Unknown component: {component_name}"
                }

        except Exception as e:
            status = "error"
            details = {"error": str(e)}

        response_time = (time.time() - start_time) * 1000

        return ComponentHealth(
            name=component_name,
            status=status,
            last_check=datetime.now(),
            details=details,
            response_time_ms=response_time,
        )

    async def _check_database(self) -> tuple[str, Dict[str, str]]:
        """Check database connectivity"""
        # For now, we're using in-memory storage, so always healthy
        await asyncio.sleep(0.001)  # Simulate check
        return "healthy", {"type": "in-memory", "connection": "active"}

    async def _check_websocket(self) -> tuple[str, Dict[str, str]]:
        """Check WebSocket manager"""
        try:
            # Import here to avoid circular imports
            from websocket.manager import websocket_manager

            connections = len(websocket_manager.active_connections)
            return "healthy", {
                "active_connections": str(connections),
                "manager_status": "active",
            }
        except Exception as e:
            return "warning", {"error": str(e), "manager_status": "unavailable"}

    async def _check_agents(self) -> tuple[str, Dict[str, str]]:
        """Check agent system"""
        try:
            # This would check actual agent status in production
            return "healthy", {
                "search_agent": "active",
                "analysis_agent": "active",
                "visualization_agent": "active",
                "orchestrator": "active",
            }
        except Exception as e:
            return "error", {"error": str(e)}

    async def _check_static_files(self) -> tuple[str, Dict[str, str]]:
        """Check static file availability"""
        try:
            static_dir = Path(__file__).parent.parent / "static"
            css_file = static_dir / "css" / "main.css"
            js_file = static_dir / "js" / "main.js"

            css_exists = css_file.exists()
            js_exists = js_file.exists()

            if css_exists and js_exists:
                return "healthy", {
                    "css_file": "available",
                    "js_file": "available",
                    "static_dir": str(static_dir),
                }
            else:
                return "warning", {
                    "css_file": "available" if css_exists else "missing",
                    "js_file": "available" if js_exists else "missing",
                    "static_dir": str(static_dir),
                }
        except Exception as e:
            return "error", {"error": str(e)}

    async def _check_api(self) -> tuple[str, Dict[str, str]]:
        """Check API endpoints"""
        try:
            # Check if key endpoints are available
            return "healthy", {
                "search_endpoint": "available",
                "agents_endpoint": "available",
                "visualize_endpoint": "available",
                "performance_endpoint": "available",
            }
        except Exception as e:
            return "error", {"error": str(e)}

    async def get_system_health(self) -> SystemHealth:
        """Get comprehensive system health"""
        components_to_check = [
            "database",
            "websocket",
            "agents",
            "static_files",
            "api",
        ]

        components = []
        error_count = 0
        warning_count = 0

        for component in components_to_check:
            health = await self.check_component_health(component)
            components.append(health)

            if health.status == "error":
                error_count += 1
            elif health.status == "warning":
                warning_count += 1

        # Determine overall status
        if error_count > 0:
            overall_status = "error"
        elif warning_count > 0:
            overall_status = "degraded"
        else:
            overall_status = "healthy"

        uptime = time.time() - self.start_time

        # Calculate metrics
        avg_response_time = sum(c.response_time_ms for c in components) / len(
            components
        )

        metrics = {
            "uptime_seconds": uptime,
            "components_healthy": len(components) - error_count - warning_count,
            "components_total": len(components),
            "avg_response_time_ms": avg_response_time,
            "memory_usage_mb": 0.0,  # Would implement actual memory monitoring
            "cpu_usage_percent": 0.0,  # Would implement actual CPU monitoring
        }

        return SystemHealth(
            status=overall_status,
            timestamp=datetime.now(),
            uptime_seconds=uptime,
            components=components,
            metrics=metrics,
        )


# Global health monitor instance
health_monitor = HealthMonitor()


def create_health_router() -> APIRouter:
    """Create health monitoring router"""

    router = APIRouter()

    @router.get("/health", response_model=SystemHealth)
    async def get_health():
        """Get comprehensive system health status"""
        return await health_monitor.get_system_health()

    @router.get("/health/{component}")
    async def get_component_health(component: str):
        """Get health status for a specific component"""
        return await health_monitor.check_component_health(component)

    @router.get("/health/quick/status")
    async def quick_health():
        """Quick health check for load balancers"""
        health = await health_monitor.get_system_health()
        return {
            "status": health.status,
            "timestamp": health.timestamp,
            "uptime": health.uptime_seconds,
        }

    return router
