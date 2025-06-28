"""
Unified GEO Client Interface

This module provides a unified interface to all GEO-related tools:
- entrezpy: NCBI E-utilities access
- GEOparse: GEO SOFT file parsing
- pysradb: SRA metadata retrieval
- geofetch: Standardized data download
"""

import asyncio
import hashlib
import json
import logging
import ssl
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiohttp

try:
    from GEOparse import get_GEO

    HAS_GEOPARSE = True
except ImportError:
    HAS_GEOPARSE = False

try:
    from pysradb import SRAweb

    HAS_PYSRADB = True
except ImportError:
    HAS_PYSRADB = False

from ..core.config import Config
from ..core.exceptions import GEOClientError, GEOParseError, NCBIAPIError, SRAError

logger = logging.getLogger(__name__)


class NCBIDirectClient:
    """Direct NCBI E-utilities client using requests/aiohttp."""

    BASE_URL = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/"

    def __init__(
        self,
        email: str,
        api_key: Optional[str] = None,
        verify_ssl: bool = True,
    ):
        """
        Initialize NCBI client.

        Args:
            email: Required email for NCBI API
            api_key: Optional API key for higher rate limits
            verify_ssl: Whether to verify SSL certificates
        """
        self.email = email
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.session = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self.session is None:
            # Create SSL context
            ssl_context = None
            if not self.verify_ssl:
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                logger.warning("SSL verification disabled for NCBI API - " + "use only for testing")

            connector = aiohttp.TCPConnector(ssl=ssl_context)
            self.session = aiohttp.ClientSession(connector=connector)
        return self.session

    async def close(self) -> None:
        """Close the aiohttp session."""
        if self.session:
            await self.session.close()
            self.session = None

    def _build_params(self, **kwargs) -> Dict[str, str]:
        """Build parameters for NCBI API call."""
        params = {
            "email": self.email,
            "tool": "omics_oracle",
        }
        if self.api_key:
            params["api_key"] = self.api_key

        # Add additional parameters
        params.update(kwargs)
        return params

    async def esearch(self, db: str, term: str, retmax: int = 20, retstart: int = 0, **kwargs) -> List[str]:
        """
        Search NCBI database and return list of IDs.

        Args:
            db: Database to search (e.g., 'gds' for GEO DataSets)
            term: Search term
            retmax: Maximum number of results
            retstart: Starting position
            **kwargs: Additional parameters

        Returns:
            List of NCBI IDs
        """
        url = f"{self.BASE_URL}esearch.fcgi"
        params = self._build_params(
            db=db,
            term=term,
            retmax=str(retmax),
            retstart=str(retstart),
            retmode="json",
            **kwargs,
        )

        session = await self._get_session()
        try:
            async with session.get(url, params=params) as response:
                response.raise_for_status()
                data = await response.json()

                # Extract IDs from NCBI JSON response
                esearch_result = data.get("esearchresult", {})
                id_list = esearch_result.get("idlist", [])

                logger.debug(
                    "NCBI esearch returned %d results for query: %s",
                    len(id_list),
                    term,
                )
                return id_list

        except aiohttp.ClientError as e:
            raise NCBIAPIError(f"NCBI API request failed: {e}") from e
        except (KeyError, ValueError) as e:
            raise NCBIAPIError(f"Failed to parse NCBI response: {e}") from e

    async def efetch(
        self,
        db: str,
        ids: List[str],
        rettype: str = "xml",
        retmode: str = "xml",
        **kwargs,
    ) -> str:
        """
        Fetch records from NCBI database.

        Args:
            db: Database name
            ids: List of record IDs
            rettype: Return type (xml, json, etc.)
            retmode: Return mode
            **kwargs: Additional parameters

        Returns:
            Raw response content
        """
        if not ids:
            return ""

        url = f"{self.BASE_URL}efetch.fcgi"
        params = self._build_params(db=db, id=",".join(ids), rettype=rettype, retmode=retmode, **kwargs)

        session = await self._get_session()
        try:
            async with session.get(url, params=params) as response:
                response.raise_for_status()
                content = await response.text()

                logger.debug(
                    "NCBI efetch returned %d chars for %d IDs",
                    len(content),
                    len(ids),
                )
                return content

        except aiohttp.ClientError as e:
            raise NCBIAPIError(f"NCBI API request failed: {e}") from e


class SimpleCache:
    """Simple file-based cache for GEO metadata."""

    def __init__(self, cache_dir: Path, default_ttl: int = 3600):
        """
        Initialize cache.

        Args:
            cache_dir: Directory for cache files
            default_ttl: Default time-to-live in seconds
        """
        self.cache_dir = cache_dir
        self.default_ttl = default_ttl
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_cache_path(self, key: str) -> Path:
        """Get cache file path for a key."""
        # Use hash to create safe filename (non-security use)
        key_hash = hashlib.md5(key.encode(), usedforsecurity=False).hexdigest()  # nosec B324
        return self.cache_dir / f"{key_hash}.json"

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Get cached data if valid."""
        cache_path = self._get_cache_path(key)

        if not cache_path.exists():
            return None

        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                cache_data = json.load(f)

            # Check if cache is still valid
            if time.time() - cache_data.get("timestamp", 0) > self.default_ttl:
                # Cache expired, remove it
                cache_path.unlink(missing_ok=True)
                return None

            return cache_data.get("data")
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to read cache for %s: %s", key, str(e))
            cache_path.unlink(missing_ok=True)
            return None

    def set(self, key: str, data: Dict[str, Any]) -> None:
        """Cache data."""
        cache_path = self._get_cache_path(key)

        cache_data = {"timestamp": time.time(), "data": data}

        try:
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(cache_data, f, ensure_ascii=True, indent=2)
        except (OSError, TypeError) as e:
            logger.warning("Failed to cache data for %s: %s", key, str(e))


class RateLimiter:
    """Simple rate limiter for API calls."""

    def __init__(self, max_calls: int, time_window: float):
        """
        Initialize rate limiter.

        Args:
            max_calls: Maximum calls allowed in time window
            time_window: Time window in seconds
        """
        self.max_calls = max_calls
        self.time_window = time_window
        self.calls = []

    async def acquire(self) -> None:
        """Acquire permission for an API call."""
        now = time.time()

        # Remove old calls outside the time window
        self.calls = [call_time for call_time in self.calls if now - call_time < self.time_window]

        # If we've hit the limit, wait
        if len(self.calls) >= self.max_calls:
            wait_time = self.time_window - (now - self.calls[0])
            if wait_time > 0:
                logger.debug("Rate limit reached, waiting %.2f seconds", wait_time)
                await asyncio.sleep(wait_time)
                return await self.acquire()  # Retry after waiting

        # Record this call
        self.calls.append(now)


async def retry_with_backoff(func, max_retries: int = 3, initial_delay: float = 1.0):
    """
    Retry a function with exponential backoff.

    Args:
        func: Async function to retry
        max_retries: Maximum number of retry attempts
        initial_delay: Initial delay between retries

    Returns:
        Result of the function call

    Raises:
        Last exception if all retries fail
    """
    last_exception = None
    delay = initial_delay

    for attempt in range(max_retries + 1):
        try:
            return await func()
        except Exception as e:
            last_exception = e
            if attempt == max_retries:
                break

            logger.warning(
                "Attempt %d failed: %s. Retrying in %.2f seconds",
                attempt + 1,
                str(e),
                delay,
            )
            await asyncio.sleep(delay)
            delay *= 2  # Exponential backoff

    if last_exception:
        raise last_exception
    raise RuntimeError("All retry attempts failed")


class UnifiedGEOClient:
    """
    Unified client for accessing GEO data through multiple tools.

    Provides a single interface for:
    - Searching GEO database
    - Retrieving metadata
    - Parsing SOFT files
    - Accessing SRA information
    """

    def __init__(self, config: Optional[Config] = None):
        """Initialize the unified GEO client."""
        self.config = config or Config()

        # Initialize rate limiter for NCBI API
        # Default: 3 requests per second (NCBI guideline)
        self.rate_limiter = RateLimiter(max_calls=self.config.ncbi.rate_limit, time_window=1.0)

        # Initialize cache
        self.cache = SimpleCache(
            cache_dir=Path(self.config.cache.directory),
            default_ttl=self.config.cache.default_ttl,
        )

        self._setup_clients()

    def _setup_clients(self) -> None:
        """Initialize all GEO tool clients."""
        # Initialize direct NCBI client
        if self.config.ncbi.email:
            try:
                # Use SSL verification disabled for development/testing
                # to avoid certificate issues
                self.ncbi_client = NCBIDirectClient(
                    email=self.config.ncbi.email,
                    api_key=self.config.ncbi.api_key,
                    verify_ssl=False,  # Disable SSL for testing
                )
                logger.info("Direct NCBI client initialized " "(SSL verification disabled)")
            except Exception as e:
                logger.error("Failed to initialize NCBI client: %s", str(e))
                self.ncbi_client = None
        else:
            logger.warning("NCBI client not available - no email configured")
            self.ncbi_client = None

        if not HAS_PYSRADB:
            logger.warning("SRA client not available")
            self.sra_client = None
        else:
            # Initialize SRA web client
            try:
                self.sra_client = SRAweb()
            except Exception as e:
                logger.error("Failed to initialize SRA client: %s", str(e))
                self.sra_client = None

        logger.info("Unified GEO client initialized successfully")

    def _get_cached_data(self, key: str) -> Optional[Any]:
        """DEPRECATED: Cache disabled for fresh data - returns None."""
        # Cache disabled for user-facing results to ensure freshness
        return None

    def _cache_data(self, key: str, data: Any) -> None:
        """Cache data for debugging/analysis only - not used for serving results."""
        # Log for debugging/analysis purposes only
        logger.debug(f"Caching key for analysis: {key} (not used for serving results)")
        # Still cache for debugging but don't use for serving
        self.cache.set(key, data)

    async def close(self) -> None:
        """Clean up resources."""
        if hasattr(self, "ncbi_client") and self.ncbi_client:
            await self.ncbi_client.close()

    def _convert_ncbi_id_to_gse(self, ncbi_id: str) -> str:
        """
        Convert NCBI numeric ID to GSE format.

        NCBI returns IDs like '200096615' where:
        - '200' is a prefix for GEO series
        - '096615' is the actual GSE number (GSE96615)

        Args:
            ncbi_id: NCBI numeric ID (e.g., '200096615')

        Returns:
            GSE format ID (e.g., 'GSE96615')
        """
        if not ncbi_id.isdigit():
            return ncbi_id  # Already in correct format

        # Handle GEO series IDs that start with 200
        if ncbi_id.startswith("200") and len(ncbi_id) > 3:
            # Remove '200' prefix and any leading zeros
            gse_number = ncbi_id[3:].lstrip("0")
            if gse_number:  # Make sure we don't have an empty string
                return f"GSE{gse_number}"

        # For other numeric IDs, try to identify the pattern
        # This is a fallback for other potential prefixes
        if len(ncbi_id) >= 6:
            # Try to find a reasonable GSE number
            for prefix_len in [3, 2, 1]:
                if len(ncbi_id) > prefix_len:
                    candidate = ncbi_id[prefix_len:].lstrip("0")
                    # Reasonable GSE number
                    if candidate and len(candidate) >= 3:
                        return f"GSE{candidate}"

        # If all else fails, return as-is (will likely fail downstream)
        logger.warning(f"Could not convert NCBI ID {ncbi_id} to GSE format")
        return ncbi_id

    async def search_geo_series(
        self,
        query: str,
        max_results: int = 100,
    ) -> List[str]:
        """
        Search GEO database for series matching query.

        Args:
            query: Search query (e.g., 'breast cancer AND gse')
            max_results: Maximum number of results to return

        Returns:
            List of GEO series IDs (GSE numbers)
        """
        if not self.ncbi_client:
            raise GEOClientError("NCBI client not available - check email configuration")

        # Apply rate limiting
        await self.rate_limiter.acquire()

        # Check cache first
        cache_key = f"search_geo_series_{query}_{max_results}"
        cached_result = self._get_cached_data(cache_key)
        if cached_result is not None:
            return cached_result

        async def _search():
            # Search GEO DataSets database
            results = await self.ncbi_client.esearch(
                db="gds",
                term=query,
                retmax=max_results,
            )
            return results

        try:
            results = await retry_with_backoff(_search)

            # Convert NCBI numeric IDs to GSE format
            gse_results = []
            for ncbi_id in results:
                gse_id = self._convert_ncbi_id_to_gse(ncbi_id)
                gse_results.append(gse_id)
                logger.debug(f"Converted NCBI ID {ncbi_id} -> {gse_id}")

            # Cache results (cache the converted GSE IDs)
            self._cache_data(cache_key, gse_results)

            logger.info("Found %d GEO series for query: %s", len(gse_results), query)
            return gse_results

        except NCBIAPIError as e:
            raise GEOClientError(f"Failed to search GEO: {e}") from e
        except Exception as e:
            logger.error("Error searching GEO database: %s", str(e))
            raise GEOClientError(f"Unexpected error during GEO search: {e}") from e

    async def get_geo_metadata(self, geo_id: str, include_sra: bool = True) -> Dict[str, Any]:
        """
        Retrieve comprehensive metadata for a GEO series.

        Args:
            geo_id: GEO series ID (e.g., 'GSE123456')
            include_sra: Whether to include SRA metadata

        Returns:
            Dictionary containing all available metadata
        """
        if not HAS_GEOPARSE:
            raise GEOClientError("GEOparse not available")

        # CACHE REMOVED: Always fetch fresh GEO metadata for accurate results
        logger.info("Retrieving fresh metadata for %s (cache disabled)", geo_id)

        try:
            logger.info("Retrieving metadata for %s", geo_id)

            # Parse GEO series using GEOparse
            gse = get_GEO(geo_id, destdir=str(self.config.cache.directory))

            # Extract basic metadata
            metadata = {
                "geo_id": geo_id,
                "title": getattr(gse, "metadata", {}).get("title", [""])[0],
                "summary": getattr(gse, "metadata", {}).get("summary", [""])[0],
                "overall_design": getattr(gse, "metadata", {}).get("overall_design", [""])[0],
                "organism": getattr(gse, "metadata", {}).get("taxon", [""])[0],
                "submission_date": getattr(gse, "metadata", {}).get("submission_date", [""])[0],
                "last_update_date": getattr(gse, "metadata", {}).get("last_update_date", [""])[0],
                "contact_name": getattr(gse, "metadata", {}).get("contact_name", [""]),
                "contact_email": getattr(gse, "metadata", {}).get("contact_email", [""]),
                "platform_count": len(getattr(gse, "gpls", {})),
                "sample_count": len(getattr(gse, "gsms", {})),
                "platforms": list(getattr(gse, "gpls", {}).keys()),
                "samples": list(getattr(gse, "gsms", {}).keys()),
            }

            # Add SRA metadata if requested
            if include_sra and HAS_PYSRADB and self.sra_client:
                try:
                    sra_metadata = await self._get_sra_metadata(geo_id)
                    metadata["sra_info"] = sra_metadata
                except SRAError as e:
                    logger.warning("Could not retrieve SRA data for %s: %s", geo_id, str(e))
                    metadata["sra_info"] = None

            # Log for query flow analysis (no caching of user-facing results)
            cache_key = f"metadata_{geo_id}_{include_sra}"
            logger.info("Successfully retrieved fresh metadata for %s (key: %s)", geo_id, cache_key)

            logger.info("Successfully retrieved metadata for %s", geo_id)
            return metadata

        except Exception as e:
            logger.error("Error retrieving metadata for %s: %s", geo_id, str(e))
            raise GEOParseError(f"Failed to get metadata for {geo_id}: {str(e)}") from e

    async def _get_sra_metadata(self, geo_id: str) -> Optional[Dict[str, Any]]:
        """Get SRA metadata for a GEO series."""
        if not HAS_PYSRADB or self.sra_client is None:
            return None

        try:
            # Query SRA database for the GEO ID
            df = self.sra_client.gse_to_srp(geo_id)
            if df.empty:
                return None

            # Convert to dictionary format
            sra_info = {
                "srp_ids": df["study_accession"].unique().tolist(),
                "run_count": len(df),
                "experiment_count": df["experiment_accession"].nunique(),
                "sample_count": df["sample_accession"].nunique(),
                "total_spots": (df["total_spots"].sum() if "total_spots" in df else 0),
                "total_bases": (df["total_bases"].sum() if "total_bases" in df else 0),
            }

            return sra_info

        except Exception as e:
            logger.debug("SRA metadata not available for %s: %s", geo_id, str(e))
            raise SRAError(f"Failed to retrieve SRA data for {geo_id}") from e

    async def batch_retrieve_metadata(
        self, geo_ids: List[str], max_concurrent: int = 5
    ) -> Dict[str, Dict[str, Any]]:
        """
        Retrieve metadata for multiple GEO series concurrently.

        Args:
            geo_ids: List of GEO series IDs
            max_concurrent: Maximum concurrent requests

        Returns:
            Dictionary mapping GEO IDs to their metadata
        """
        semaphore = asyncio.Semaphore(max_concurrent)

        async def get_single_metadata(
            geo_id: str,
        ) -> tuple[str, Dict[str, Any]]:
            async with semaphore:
                try:
                    metadata = await self.get_geo_metadata(geo_id)
                    return geo_id, metadata
                except GEOClientError as e:
                    logger.error("Failed to get metadata for %s: %s", geo_id, str(e))
                    return geo_id, {"error": str(e)}

        # Execute all requests concurrently
        tasks = [get_single_metadata(geo_id) for geo_id in geo_ids]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Compile results
        metadata_dict = {}
        for result in results:
            if isinstance(result, Exception):
                logger.error("Batch retrieval error: %s", str(result))
                continue
            if isinstance(result, tuple) and len(result) == 2:
                geo_id, metadata = result
                metadata_dict[geo_id] = metadata

        logger.info(
            "Retrieved metadata for %d out of %d series",
            len(metadata_dict),
            len(geo_ids),
        )
        return metadata_dict

    def validate_geo_id(self, geo_id: str) -> bool:
        """
        Validate GEO series ID format.

        Args:
            geo_id: GEO series ID to validate

        Returns:
            True if valid, False otherwise
        """
        if not isinstance(geo_id, str):
            return False

        # GSE followed by digits
        return geo_id.upper().startswith("GSE") and geo_id[3:].isdigit()

    def get_client_info(self) -> Dict[str, str]:
        """Get information about configured clients."""
        return {
            "entrez_email": self.config.ncbi.email or "not_configured",
            "entrez_api_key": ("configured" if self.config.ncbi.api_key else "not_set"),
            "cache_directory": str(self.config.cache.directory),
            "rate_limit": str(self.config.ncbi.rate_limit),
            "has_entrez": str(hasattr(self, "ncbi_client") and self.ncbi_client is not None),
            "has_geoparse": str(HAS_GEOPARSE),
            "has_pysradb": str(HAS_PYSRADB),
        }
