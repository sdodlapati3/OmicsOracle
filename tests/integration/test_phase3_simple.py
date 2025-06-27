"""
Simple test to validate Phase 3 architecture components.
"""

import sys
from pathlib import Path

import pytest

# Add project root to Python path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))


@pytest.mark.asyncio
async def test_event_bus_creation():
    """Test that we can create an event bus."""
    from src.omics_oracle.infrastructure.messaging.event_bus import EventBus

    event_bus = EventBus()
    assert event_bus is not None

    # Test basic operations
    subscriber_count = event_bus.get_subscriber_count(str)
    assert subscriber_count == 0


@pytest.mark.asyncio
async def test_memory_cache_creation():
    """Test that we can create a memory cache."""
    from src.omics_oracle.infrastructure.caching.memory_cache import MemoryCache

    cache = MemoryCache()
    assert cache is not None

    # Test basic operations
    await cache.set("test", "value")
    value = await cache.get("test")
    assert value == "value"


@pytest.mark.asyncio
async def test_container_creation():
    """Test that we can create a dependency container."""
    from src.omics_oracle.infrastructure.dependencies.container import Container

    container = Container()
    assert container is not None

    # Test registration
    await container.register_singleton(str, "test_value")
    value = await container.get(str)
    assert value == "test_value"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
