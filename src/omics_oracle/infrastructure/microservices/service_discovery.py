"""
Microservices Infrastructure for Service Discovery and Communication
"""

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Union
from urllib.parse import urljoin

import aiohttp
import httpx


class ServiceStatus(Enum):
    """Service status enumeration"""

    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    STARTING = "starting"
    STOPPING = "stopping"
    UNKNOWN = "unknown"


class ServiceType(Enum):
    """Service type enumeration"""

    SEARCH_SERVICE = "search_service"
    AI_SERVICE = "ai_service"
    DATA_SERVICE = "data_service"
    NOTIFICATION_SERVICE = "notification_service"
    AUTH_SERVICE = "auth_service"
    GATEWAY_SERVICE = "gateway_service"


@dataclass
class ServiceEndpoint:
    """Service endpoint information"""

    host: str
    port: int
    path: str = "/"
    protocol: str = "http"

    @property
    def url(self) -> str:
        """Get full URL for the endpoint"""
        return f"{self.protocol}://{self.host}:{self.port}{self.path}"

    def __str__(self) -> str:
        return self.url


@dataclass
class ServiceInfo:
    """Service information for discovery"""

    service_id: str
    service_name: str
    service_type: ServiceType
    version: str
    endpoint: ServiceEndpoint

    # Health and status
    status: ServiceStatus = ServiceStatus.STARTING
    last_heartbeat: float = field(default_factory=time.time)
    health_check_url: Optional[str] = None

    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: Set[str] = field(default_factory=set)

    # Load balancing
    weight: int = 100
    max_connections: int = 100
    current_connections: int = 0

    # Timing
    registered_at: float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)

    def update_heartbeat(self):
        """Update heartbeat timestamp"""
        self.last_heartbeat = time.time()
        self.last_updated = time.time()

    def is_healthy(self, timeout: int = 30) -> bool:
        """Check if service is healthy based on heartbeat"""
        if self.status != ServiceStatus.HEALTHY:
            return False

        return (time.time() - self.last_heartbeat) < timeout

    def get_load_factor(self) -> float:
        """Calculate current load factor (0.0 to 1.0)"""
        if self.max_connections == 0:
            return 0.0
        return min(1.0, self.current_connections / self.max_connections)


class ServiceRegistry:
    """
    Service registry for microservices discovery
    """

    def __init__(self, heartbeat_timeout: int = 30):
        self.heartbeat_timeout = heartbeat_timeout

        # Service storage
        self._services: Dict[str, ServiceInfo] = {}  # service_id -> ServiceInfo
        self._services_by_name: Dict[
            str, List[str]
        ] = {}  # service_name -> [service_ids]
        self._services_by_type: Dict[
            ServiceType, List[str]
        ] = {}  # service_type -> [service_ids]

        # Event callbacks
        self._registration_callbacks: List[Callable] = []
        self._deregistration_callbacks: List[Callable] = []
        self._health_change_callbacks: List[Callable] = []

        # Health monitoring
        self._health_monitor_task: Optional[asyncio.Task] = None
        self._running = False

        self.logger = logging.getLogger(__name__)

    async def start(self):
        """Start the service registry"""
        self.logger.info("Starting service registry")

        self._running = True

        # Start health monitoring
        self._health_monitor_task = asyncio.create_task(self._health_monitor())

        self.logger.info("Service registry started")

    async def stop(self):
        """Stop the service registry"""
        self.logger.info("Stopping service registry")

        self._running = False

        # Stop health monitoring
        if self._health_monitor_task:
            self._health_monitor_task.cancel()
            try:
                await self._health_monitor_task
            except asyncio.CancelledError:
                pass

        self.logger.info("Service registry stopped")

    async def register_service(self, service_info: ServiceInfo) -> bool:
        """Register a service"""
        try:
            service_id = service_info.service_id

            # Store service
            self._services[service_id] = service_info

            # Index by name
            if service_info.service_name not in self._services_by_name:
                self._services_by_name[service_info.service_name] = []
            self._services_by_name[service_info.service_name].append(service_id)

            # Index by type
            if service_info.service_type not in self._services_by_type:
                self._services_by_type[service_info.service_type] = []
            self._services_by_type[service_info.service_type].append(service_id)

            # Set status to healthy
            service_info.status = ServiceStatus.HEALTHY
            service_info.update_heartbeat()

            # Notify callbacks
            for callback in self._registration_callbacks:
                try:
                    await callback(service_info)
                except Exception as e:
                    self.logger.error(f"Registration callback error: {e}")

            self.logger.info(
                f"Service registered: {service_info.service_name} ({service_id})"
            )
            return True

        except Exception as e:
            self.logger.error(
                f"Failed to register service {service_info.service_id}: {e}"
            )
            return False

    async def deregister_service(self, service_id: str) -> bool:
        """Deregister a service"""
        try:
            if service_id not in self._services:
                return False

            service_info = self._services[service_id]

            # Remove from indices
            if service_info.service_name in self._services_by_name:
                self._services_by_name[service_info.service_name].remove(
                    service_id
                )
                if not self._services_by_name[service_info.service_name]:
                    del self._services_by_name[service_info.service_name]

            if service_info.service_type in self._services_by_type:
                self._services_by_type[service_info.service_type].remove(
                    service_id
                )
                if not self._services_by_type[service_info.service_type]:
                    del self._services_by_type[service_info.service_type]

            # Remove service
            del self._services[service_id]

            # Notify callbacks
            for callback in self._deregistration_callbacks:
                try:
                    await callback(service_info)
                except Exception as e:
                    self.logger.error(f"Deregistration callback error: {e}")

            self.logger.info(
                f"Service deregistered: {service_info.service_name} ({service_id})"
            )
            return True

        except Exception as e:
            self.logger.error(f"Failed to deregister service {service_id}: {e}")
            return False

    async def update_heartbeat(self, service_id: str) -> bool:
        """Update service heartbeat"""
        if service_id in self._services:
            self._services[service_id].update_heartbeat()
            return True
        return False

    async def update_service_status(
        self, service_id: str, status: ServiceStatus
    ):
        """Update service status"""
        if service_id in self._services:
            old_status = self._services[service_id].status
            self._services[service_id].status = status
            self._services[service_id].last_updated = time.time()

            # Notify health change callbacks
            if old_status != status:
                for callback in self._health_change_callbacks:
                    try:
                        await callback(
                            self._services[service_id], old_status, status
                        )
                    except Exception as e:
                        self.logger.error(f"Health change callback error: {e}")

    def get_service(self, service_id: str) -> Optional[ServiceInfo]:
        """Get service by ID"""
        return self._services.get(service_id)

    def get_services_by_name(self, service_name: str) -> List[ServiceInfo]:
        """Get all services with a specific name"""
        service_ids = self._services_by_name.get(service_name, [])
        return [
            self._services[sid] for sid in service_ids if sid in self._services
        ]

    def get_services_by_type(
        self, service_type: ServiceType
    ) -> List[ServiceInfo]:
        """Get all services of a specific type"""
        service_ids = self._services_by_type.get(service_type, [])
        return [
            self._services[sid] for sid in service_ids if sid in self._services
        ]

    def get_healthy_services(
        self,
        service_name: Optional[str] = None,
        service_type: Optional[ServiceType] = None,
    ) -> List[ServiceInfo]:
        """Get healthy services, optionally filtered by name or type"""
        services = []

        if service_name:
            services = self.get_services_by_name(service_name)
        elif service_type:
            services = self.get_services_by_type(service_type)
        else:
            services = list(self._services.values())

        return [s for s in services if s.is_healthy(self.heartbeat_timeout)]

    def list_all_services(self) -> List[ServiceInfo]:
        """List all registered services"""
        return list(self._services.values())

    async def _health_monitor(self):
        """Monitor service health and cleanup stale services"""
        while self._running:
            try:
                current_time = time.time()
                stale_services = []

                for service_id, service_info in self._services.items():
                    # Check if service is stale
                    if (
                        current_time - service_info.last_heartbeat
                    ) > self.heartbeat_timeout:
                        stale_services.append(service_id)

                        # Update status to unhealthy
                        if service_info.status == ServiceStatus.HEALTHY:
                            await self.update_service_status(
                                service_id, ServiceStatus.UNHEALTHY
                            )

                # Remove very stale services (2x timeout)
                very_stale_timeout = self.heartbeat_timeout * 2
                for service_id in stale_services:
                    service_info = self._services[service_id]
                    if (
                        current_time - service_info.last_heartbeat
                    ) > very_stale_timeout:
                        await self.deregister_service(service_id)

                await asyncio.sleep(10)  # Check every 10 seconds

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Health monitor error: {e}")
                await asyncio.sleep(10)

    # Callback management
    def add_registration_callback(self, callback: Callable):
        """Add callback for service registration"""
        self._registration_callbacks.append(callback)

    def add_deregistration_callback(self, callback: Callable):
        """Add callback for service deregistration"""
        self._deregistration_callbacks.append(callback)

    def add_health_change_callback(self, callback: Callable):
        """Add callback for service health changes"""
        self._health_change_callbacks.append(callback)

    def get_statistics(self) -> Dict[str, Any]:
        """Get registry statistics"""
        service_count_by_type = {}
        healthy_count_by_type = {}

        for service_type in ServiceType:
            services = self.get_services_by_type(service_type)
            healthy_services = [
                s for s in services if s.is_healthy(self.heartbeat_timeout)
            ]

            service_count_by_type[service_type.value] = len(services)
            healthy_count_by_type[service_type.value] = len(healthy_services)

        return {
            "total_services": len(self._services),
            "healthy_services": len(
                [
                    s
                    for s in self._services.values()
                    if s.is_healthy(self.heartbeat_timeout)
                ]
            ),
            "service_types": len(self._services_by_type),
            "service_names": len(self._services_by_name),
            "services_by_type": service_count_by_type,
            "healthy_by_type": healthy_count_by_type,
        }


class LoadBalancer:
    """
    Load balancer for microservices
    """

    def __init__(self, registry: ServiceRegistry):
        self.registry = registry

        # Round-robin state
        self._round_robin_state: Dict[str, int] = {}

        self.logger = logging.getLogger(__name__)

    def select_service(
        self, service_name: str, strategy: str = "round_robin"
    ) -> Optional[ServiceInfo]:
        """
        Select a service instance using load balancing strategy
        """
        healthy_services = self.registry.get_healthy_services(
            service_name=service_name
        )

        if not healthy_services:
            return None

        if strategy == "round_robin":
            return self._round_robin_select(service_name, healthy_services)
        elif strategy == "least_connections":
            return self._least_connections_select(healthy_services)
        elif strategy == "weighted":
            return self._weighted_select(healthy_services)
        elif strategy == "random":
            import random

            return random.choice(healthy_services)
        else:
            # Default to round-robin
            return self._round_robin_select(service_name, healthy_services)

    def _round_robin_select(
        self, service_name: str, services: List[ServiceInfo]
    ) -> ServiceInfo:
        """Round-robin service selection"""
        if service_name not in self._round_robin_state:
            self._round_robin_state[service_name] = 0

        index = self._round_robin_state[service_name] % len(services)
        self._round_robin_state[service_name] += 1

        return services[index]

    def _least_connections_select(
        self, services: List[ServiceInfo]
    ) -> ServiceInfo:
        """Select service with least connections"""
        return min(services, key=lambda s: s.current_connections)

    def _weighted_select(self, services: List[ServiceInfo]) -> ServiceInfo:
        """Weighted service selection"""
        import random

        # Calculate total weight
        total_weight = sum(s.weight for s in services)

        if total_weight == 0:
            return random.choice(services)

        # Select based on weight
        pick = random.uniform(0, total_weight)
        current = 0

        for service in services:
            current += service.weight
            if current >= pick:
                return service

        return services[-1]  # Fallback


class ServiceClient:
    """
    HTTP client for inter-service communication
    """

    def __init__(
        self,
        registry: ServiceRegistry,
        load_balancer: LoadBalancer,
        timeout: int = 30,
        retry_attempts: int = 3,
    ):
        self.registry = registry
        self.load_balancer = load_balancer
        self.timeout = timeout
        self.retry_attempts = retry_attempts

        # HTTP client session
        self._session: Optional[httpx.AsyncClient] = None

        self.logger = logging.getLogger(__name__)

    async def start(self):
        """Start the service client"""
        self._session = httpx.AsyncClient(timeout=self.timeout)

    async def stop(self):
        """Stop the service client"""
        if self._session:
            await self._session.aclose()

    async def call_service(
        self,
        service_name: str,
        method: str,
        path: str,
        data: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        load_balance_strategy: str = "round_robin",
    ) -> Optional[Dict]:
        """
        Make a call to a service
        """
        if not self._session:
            await self.start()

        for attempt in range(self.retry_attempts):
            try:
                # Select service instance
                service = self.load_balancer.select_service(
                    service_name, load_balance_strategy
                )

                if not service:
                    self.logger.error(
                        f"No healthy instances of service '{service_name}' found"
                    )
                    return None

                # Construct URL
                url = urljoin(service.endpoint.url, path.lstrip("/"))

                # Prepare headers
                request_headers = {
                    "Content-Type": "application/json",
                    "X-Service-Client": "omics-oracle",
                    "X-Request-ID": str(uuid.uuid4()),
                }
                if headers:
                    request_headers.update(headers)

                # Update connection count
                service.current_connections += 1

                try:
                    # Make request
                    if method.upper() == "GET":
                        response = await self._session.get(
                            url, headers=request_headers
                        )
                    elif method.upper() == "POST":
                        response = await self._session.post(
                            url, json=data, headers=request_headers
                        )
                    elif method.upper() == "PUT":
                        response = await self._session.put(
                            url, json=data, headers=request_headers
                        )
                    elif method.upper() == "DELETE":
                        response = await self._session.delete(
                            url, headers=request_headers
                        )
                    else:
                        raise ValueError(f"Unsupported HTTP method: {method}")

                    # Check response
                    response.raise_for_status()

                    # Return JSON response
                    return response.json()

                finally:
                    # Update connection count
                    service.current_connections = max(
                        0, service.current_connections - 1
                    )

            except Exception as e:
                self.logger.error(
                    f"Service call attempt {attempt + 1} failed: {e}"
                )

                if attempt == self.retry_attempts - 1:
                    # Last attempt failed
                    return None

                # Wait before retry
                await asyncio.sleep(2**attempt)  # Exponential backoff

        return None

    async def get(
        self, service_name: str, path: str, **kwargs
    ) -> Optional[Dict]:
        """GET request to service"""
        return await self.call_service(service_name, "GET", path, **kwargs)

    async def post(
        self, service_name: str, path: str, data: Dict, **kwargs
    ) -> Optional[Dict]:
        """POST request to service"""
        return await self.call_service(
            service_name, "POST", path, data=data, **kwargs
        )

    async def put(
        self, service_name: str, path: str, data: Dict, **kwargs
    ) -> Optional[Dict]:
        """PUT request to service"""
        return await self.call_service(
            service_name, "PUT", path, data=data, **kwargs
        )

    async def delete(
        self, service_name: str, path: str, **kwargs
    ) -> Optional[Dict]:
        """DELETE request to service"""
        return await self.call_service(service_name, "DELETE", path, **kwargs)


# Global instances
service_registry = ServiceRegistry()
load_balancer = LoadBalancer(service_registry)
service_client = ServiceClient(service_registry, load_balancer)
