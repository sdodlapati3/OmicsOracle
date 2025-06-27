"""
Microservices Infrastructure Package
"""

from .service_discovery import (
    LoadBalancer,
    ServiceClient,
    ServiceEndpoint,
    ServiceInfo,
    ServiceRegistry,
    ServiceStatus,
    ServiceType,
    load_balancer,
    service_client,
    service_registry,
)

__all__ = [
    "ServiceRegistry",
    "ServiceInfo",
    "ServiceEndpoint",
    "ServiceStatus",
    "ServiceType",
    "LoadBalancer",
    "ServiceClient",
    "service_registry",
    "load_balancer",
    "service_client",
]


async def initialize_microservices_infrastructure():
    """
    Initialize microservices infrastructure
    """
    # Start service registry
    await service_registry.start()

    # Start service client
    await service_client.start()


async def shutdown_microservices_infrastructure():
    """
    Shutdown microservices infrastructure
    """
    # Stop service client
    await service_client.stop()

    # Stop service registry
    await service_registry.stop()
