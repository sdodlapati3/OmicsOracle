"""
Failover Manager

Provides failover and high availability capabilities:
- Service endpoint failover
- Health-based routing
- Automatic fallback mechanisms
- Load balancing strategies
"""

import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class FailoverStrategy(Enum):
    """Failover strategy enumeration."""

    ROUND_ROBIN = "round_robin"
    PRIORITY = "priority"
    RANDOM = "random"
    HEALTH_BASED = "health_based"


@dataclass
class FailoverConfig:
    """Configuration for failover behavior."""

    strategy: FailoverStrategy = FailoverStrategy.HEALTH_BASED
    health_check_interval: int = 30
    failure_threshold: int = 3
    recovery_threshold: int = 2


@dataclass
class ServiceEndpoint:
    """Service endpoint configuration."""

    name: str
    url: str
    priority: int = 0
    healthy: bool = True
    failure_count: int = 0
    last_check: float = 0.0


class FailoverManager:
    """Failover management system."""

    def __init__(self, config: Optional[FailoverConfig] = None):
        self.config = config or FailoverConfig()
        self._endpoints: Dict[str, List[ServiceEndpoint]] = {}
        self._current_indices: Dict[str, int] = {}

    def register_service(
        self, service_name: str, endpoints: List[ServiceEndpoint]
    ) -> None:
        """Register service endpoints."""
        self._endpoints[service_name] = endpoints
        self._current_indices[service_name] = 0
        logger.info(
            f"Registered {len(endpoints)} endpoints for service: {service_name}"
        )

    def get_healthy_endpoint(
        self, service_name: str
    ) -> Optional[ServiceEndpoint]:
        """Get healthy endpoint for service."""
        if service_name not in self._endpoints:
            return None

        endpoints = self._endpoints[service_name]
        healthy_endpoints = [ep for ep in endpoints if ep.healthy]

        if not healthy_endpoints:
            logger.warning(f"No healthy endpoints for service: {service_name}")
            return None

        if self.config.strategy == FailoverStrategy.PRIORITY:
            return min(healthy_endpoints, key=lambda ep: ep.priority)
        elif self.config.strategy == FailoverStrategy.ROUND_ROBIN:
            current_index = self._current_indices[service_name]
            endpoint = healthy_endpoints[current_index % len(healthy_endpoints)]
            self._current_indices[service_name] = (current_index + 1) % len(
                healthy_endpoints
            )
            return endpoint
        else:
            return healthy_endpoints[0]

    def mark_endpoint_unhealthy(
        self, service_name: str, endpoint_name: str
    ) -> None:
        """Mark endpoint as unhealthy."""
        if service_name in self._endpoints:
            for endpoint in self._endpoints[service_name]:
                if endpoint.name == endpoint_name:
                    endpoint.failure_count += 1
                    if endpoint.failure_count >= self.config.failure_threshold:
                        endpoint.healthy = False
                        logger.warning(
                            f"Marked endpoint {endpoint_name} as unhealthy"
                        )
                    break
