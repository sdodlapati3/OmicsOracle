"""
Basic GEO client example and test
"""

import asyncio
import logging

from omics_oracle.core.config import Config
from omics_oracle.geo_tools.geo_client import UnifiedGEOClient

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def test_geo_client():
    """Test the GEO client functionality."""
    # Initialize configuration
    config = Config()

    # Initialize GEO client
    client = UnifiedGEOClient(config)

    # Get client info
    info = client.get_client_info()
    logger.info("Client info: %s", info)

    # Test GEO ID validation
    valid_ids = ["GSE123456", "gse789", "GSE1"]
    invalid_ids = ["ABC123", "GSE", "123", ""]

    for geo_id in valid_ids + invalid_ids:
        is_valid = client.validate_geo_id(geo_id)
        logger.info("GEO ID %s is valid: %s", geo_id, is_valid)


if __name__ == "__main__":
    asyncio.run(test_geo_client())
