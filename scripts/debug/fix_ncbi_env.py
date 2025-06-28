#!/usr/bin/env python
"""
Fix NCBI Email Environment Issue

This script loads the NCBI_EMAIL from .env.local and sets it as an environment variable
that will be used by the OmicsOracle application. It also modifies the server startup
script to ensure the environment variables are properly loaded.
"""

import logging
import os
import sys
from pathlib import Path

import dotenv

# Set up logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("env_fixer")


def fix_env_loading():
    """Fix environment variable loading for NCBI email."""
    project_root = Path.cwd()
    env_file = project_root / ".env.local"

    if not env_file.exists():
        logger.info(f"Creating {env_file}")
        with open(env_file, "w") as f:
            f.write("NCBI_EMAIL=omicsoracle@example.com\n")

    # Load the environment variables
    dotenv.load_dotenv(env_file)

    # Check if NCBI_EMAIL is set
    ncbi_email = os.environ.get("NCBI_EMAIL")
    if ncbi_email:
        logger.info(f"NCBI_EMAIL is set to: {ncbi_email}")
    else:
        # Set it manually
        os.environ["NCBI_EMAIL"] = "omicsoracle@example.com"
        logger.info("NCBI_EMAIL manually set to: omicsoracle@example.com")

    # Create a temporary Python script that will print environment variables
    temp_script = project_root / "check_env.py"
    with open(temp_script, "w") as f:
        f.write(
            """
import os
import json
import sys

# Print all environment variables
env_vars = {k: v for k, v in os.environ.items() if not k.startswith("_")}
print(json.dumps(env_vars, indent=2))

# Check specifically for NCBI_EMAIL
ncbi_email = os.environ.get("NCBI_EMAIL")
if ncbi_email:
    print(f"\\nNCBI_EMAIL is correctly set to: {ncbi_email}")
else:
    print("\\nNCBI_EMAIL is NOT set!")
    sys.exit(1)
"""
        )

    logger.info("Created environment check script")
    logger.info("Run the following command to verify: python check_env.py")

    return True


def fix_startup_script():
    """Modify the startup script to ensure environment variables are loaded."""
    project_root = Path.cwd()
    startup_script = project_root / "scripts" / "startup" / "start-futuristic-clean.sh"

    if not startup_script.exists():
        logger.warning(f"Startup script not found: {startup_script}")
        return False

    # Read the current script
    with open(startup_script, "r") as f:
        content = f.read()

    # Check if we need to add env loading
    if "dotenv" not in content:
        # Find the right spot to insert our code
        env_setup_line = "# Set environment variables"
        if env_setup_line in content:
            # Insert after this line
            new_content = content.replace(
                env_setup_line,
                f'{env_setup_line}\n\n# Load environment variables from .env files\nif [ -f "$PROJECT_ROOT/.env.local" ]; then\n    echo "🔄 Loading environment from .env.local"\n    export $(grep -v \'^#\' "$PROJECT_ROOT/.env.local" | xargs)\nfi',
            )

            # Write the updated script
            with open(startup_script, "w") as f:
                f.write(new_content)

            logger.info(f"Updated startup script: {startup_script}")
            return True
        else:
            logger.warning(f"Could not find insertion point in startup script")
    else:
        logger.info("Startup script already has environment loading")

    return False


def fix_search_service():
    """Create a wrapper for the search service that will retry with detailed logging."""
    project_root = Path.cwd()
    search_wrapper = project_root / "src" / "omics_oracle" / "services" / "search_wrapper.py"

    with open(search_wrapper, "w") as f:
        f.write(
            """
\"\"\"
Search Service Wrapper with Enhanced Error Handling and Progress Reporting

This module wraps the improved_search service to add better error handling
and detailed progress reporting.
\"\"\"

import asyncio
import logging
import os
import time
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

# Get the improved search service
from ..services.improved_search import ImprovedSearchService

logger = logging.getLogger(__name__)

def with_retries(max_retries=3, delay=1):
    \"\"\"Decorator to add retry logic to async functions.\"\"\"
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            for attempt in range(1, max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    if attempt == max_retries:
                        logger.error(f"Failed after {max_retries} attempts: {e}")
                        raise
                    logger.warning(f"Attempt {attempt} failed: {e}. Retrying in {delay}s...")
                    await asyncio.sleep(delay)
        return wrapper
    return decorator

class EnhancedSearchService:
    \"\"\"Wrapper around the ImprovedSearchService with better error handling and progress reporting.\"\"\"

    def __init__(self, *args, **kwargs):
        # Log environment for debugging
        ncbi_email = os.environ.get("NCBI_EMAIL")
        logger.info(f"NCBI_EMAIL environment variable: {ncbi_email or 'Not set'}")

        # Initialize the underlying service
        self.service = ImprovedSearchService(*args, **kwargs)

        # Copy any existing attributes
        if hasattr(self.service, 'set_progress_callback'):
            self.original_progress_callback = None

    def set_progress_callback(self, callback):
        \"\"\"Set progress callback with enhanced error handling.\"\"\"
        self.original_progress_callback = callback

        # Create a wrapped callback that handles errors
        def enhanced_callback(strategy_index, strategy_name, status):
            try:
                callback(strategy_index, strategy_name, status)
                # Log the progress event
                logger.info(f"Progress: Strategy {strategy_index} - {strategy_name} - {status}")
            except Exception as e:
                logger.error(f"Error in progress callback: {e}")

        # Set the callback on the underlying service
        if hasattr(self.service, 'set_progress_callback'):
            self.service.set_progress_callback(enhanced_callback)

    @with_retries(max_retries=2, delay=1)
    async def search_with_multiple_strategies(self, query, max_results=10):
        \"\"\"Perform search with multiple strategies, with retries and better error handling.\"\"\"
        logger.info(f"EnhancedSearchService: Searching with query: {query}")

        # Check if NCBI email is available
        ncbi_email = os.environ.get("NCBI_EMAIL")
        if not ncbi_email:
            logger.warning("NCBI_EMAIL not set in environment")
            # Try to load from .env.local
            try:
                import dotenv
                dotenv.load_dotenv(".env.local")
                ncbi_email = os.environ.get("NCBI_EMAIL")
                if ncbi_email:
                    logger.info(f"Loaded NCBI_EMAIL from .env.local: {ncbi_email}")
                else:
                    logger.warning("NCBI_EMAIL not found in .env.local")
            except ImportError:
                logger.warning("dotenv not available to load .env.local")

        # Verify the geo_client's email is set
        if hasattr(self.service, 'geo_client') and hasattr(self.service.geo_client, '_client'):
            geo_client = self.service.geo_client

            # Try to access email attribute safely
            client_email = getattr(getattr(geo_client, '_client', None), 'email', None)
            logger.info(f"GEO client email: {client_email}")

            # If email is not set but we have one in environment, try to set it
            if not client_email and ncbi_email and hasattr(geo_client, '_client'):
                try:
                    geo_client._client.email = ncbi_email
                    logger.info(f"Set GEO client email to: {ncbi_email}")
                except Exception as e:
                    logger.error(f"Could not set GEO client email: {e}")

        try:
            start_time = time.time()
            result = await self.service.search_with_multiple_strategies(query, max_results=max_results)

            # Log performance
            elapsed = time.time() - start_time
            geo_ids, metadata = result
            logger.info(f"Search completed in {elapsed:.2f}s with {len(geo_ids)} results")

            return result
        except Exception as e:
            logger.error(f"Search failed: {e}")

            # Log detailed error information
            if hasattr(self.service, 'geo_client'):
                logger.error(f"GEO client info: {self.service.geo_client}")

            # Return empty results instead of failing completely
            logger.warning("Returning empty results due to search error")
            return [], {"error": str(e), "original_query": query}
"""
        )

    logger.info(f"Created enhanced search wrapper: {search_wrapper}")
    return True


if __name__ == "__main__":
    logger.info("Fixing environment variable loading for NCBI email")

    # Fix environment loading
    fix_env_loading()

    # Fix startup script
    fix_startup_script()

    # Create search wrapper
    fix_search_service()

    logger.info("Done. Run the following command to verify:")
    logger.info(
        'python -c "import os; print(f\'NCBI_EMAIL: {os.environ.get(\\"NCBI_EMAIL\\", \\"Not set\\")}\')"'
    )
