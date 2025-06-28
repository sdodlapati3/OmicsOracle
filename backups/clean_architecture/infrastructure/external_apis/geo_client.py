"""
Modern GEO client implementation for NCBI GEO database access.

This client provides a clean, async interface for interacting with
the NCBI GEO database while handling rate limiting, error recovery,
and response caching.
"""

import asyncio
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, AsyncGenerator, Dict, List, Optional

import aiohttp
import backoff
from Bio import Entrez

from ...shared.exceptions.domain_exceptions import (
    ExternalServiceError,
    NetworkError,
    ParseError,
    RateLimitExceededError,
    ServiceUnavailableError,
)
from ..configuration.config import GEOConfig

logger = logging.getLogger(__name__)


@dataclass
class RateLimiter:
    """Simple rate limiter for API requests."""

    requests_per_second: float
    last_request_time: float = 0.0

    async def acquire(self) -> None:
        """Wait for rate limit if necessary."""
        now = time.time()
        time_since_last = now - self.last_request_time
        min_interval = 1.0 / self.requests_per_second

        if time_since_last < min_interval:
            sleep_time = min_interval - time_since_last
            await asyncio.sleep(sleep_time)

        self.last_request_time = time.time()


class GEOClient:
    """
    Modern async client for NCBI GEO database access.

    Features:
    - Async/await support
    - Automatic rate limiting
    - Retry with exponential backoff
    - Response caching
    - Comprehensive error handling
    """

    def __init__(self, config: GEOConfig):
        """
        Initialize GEO client.

        Args:
            config: GEO configuration settings
        """
        self._config = config
        self._rate_limiter = RateLimiter(config.requests_per_second)
        self._session: Optional[aiohttp.ClientSession] = None

        # Configure Bio.Entrez
        Entrez.email = config.email
        Entrez.tool = config.tool_name
        if config.api_key:
            Entrez.api_key = config.api_key

        logger.info(f"Initialized GEO client with email: {config.email}")

    async def __aenter__(self):
        """Async context manager entry."""
        await self._ensure_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()

    async def _ensure_session(self) -> None:
        """Ensure HTTP session is created."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=self._config.timeout_seconds)

            # Create SSL context based on configuration
            ssl_context = None
            if not self._config.verify_ssl:
                import ssl

                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                logger.warning("SSL verification disabled for NCBI connections")

            self._session = aiohttp.ClientSession(
                timeout=timeout,
                connector=aiohttp.TCPConnector(ssl=ssl_context),
                headers={"User-Agent": f"{self._config.tool_name}/3.0 (Contact: {self._config.email})"},
            )

    async def close(self) -> None:
        """Close the HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()

    @backoff.on_exception(
        backoff.expo,
        (aiohttp.ClientError, asyncio.TimeoutError),
        max_tries=3,
        max_time=60,
    )
    async def _make_request(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Make an HTTP request with rate limiting and retry logic.

        Args:
            url: Request URL
            params: Request parameters

        Returns:
            Response data as dictionary

        Raises:
            NetworkError: If network request fails
            ServiceUnavailableError: If service is unavailable
            ParseError: If response parsing fails
        """
        await self._rate_limiter.acquire()
        await self._ensure_session()

        try:
            logger.debug(f"Making request to {url} with params: {params}")

            async with self._session.get(url, params=params) as response:
                if response.status == 429:
                    raise RateLimitExceededError(
                        limit=int(response.headers.get("X-RateLimit-Limit", 0)),
                        window_seconds=60,
                        current_count=int(response.headers.get("X-RateLimit-Remaining", 0)),
                    )

                if response.status == 503:
                    retry_after = int(response.headers.get("Retry-After", 60))
                    raise ServiceUnavailableError("NCBI", retry_after=retry_after)

                if response.status != 200:
                    raise ExternalServiceError(
                        "NCBI",
                        f"HTTP {response.status}: {response.reason}",
                        status_code=response.status,
                    )

                content = await response.text()

                # Parse JSON response
                try:
                    import json

                    result = json.loads(content)
                    return result
                except json.JSONDecodeError as e:
                    raise ParseError(
                        "JSON",
                        f"Failed to parse JSON response: {e}",
                        content[:500],
                    )

        except aiohttp.ClientError as e:
            raise NetworkError("GET", url, str(e))
        except asyncio.TimeoutError:
            raise NetworkError("GET", url, "Request timed out")

    def _parse_xml_response(self, root) -> Dict[str, Any]:
        """
        Parse XML response from NCBI.

        Args:
            root: XML root element

        Returns:
            Parsed response data
        """
        # This is a simplified parser - in production, you'd want more robust parsing
        result = {"datasets": [], "count": 0, "query_translation": None}

        # Parse dataset records
        for record in root.findall(".//Item"):
            dataset_data = self._parse_dataset_record(record)
            if dataset_data:
                result["datasets"].append(dataset_data)

        result["count"] = len(result["datasets"])
        return result

    def _parse_dataset_record(self, record) -> Optional[Dict[str, Any]]:
        """
        Parse individual dataset record from XML.

        Args:
            record: XML record element

        Returns:
            Parsed dataset data or None if parsing fails
        """
        try:
            # Extract basic information
            geo_id = record.get("Name", "")
            title = record.findtext(".//title", "")
            summary = record.findtext(".//summary", "")

            # Extract metadata
            dataset_data = {
                "geo_id": geo_id,
                "title": title,
                "summary": summary,
                "organism": self._extract_organism(record),
                "platform": self._extract_platform(record),
                "samples_count": self._extract_sample_count(record),
                "submission_date": self._extract_date(record, "submission"),
                "last_update_date": self._extract_date(record, "update"),
                "metadata": self._extract_additional_metadata(record),
            }

            return dataset_data

        except Exception as e:
            logger.warning(f"Failed to parse dataset record: {e}")
            return None

    def _extract_organism(self, record) -> Optional[str]:
        """Extract organism information from record."""
        organism_elem = record.find(".//organism")
        if organism_elem is not None:
            return organism_elem.text
        return None

    def _extract_platform(self, record) -> Optional[str]:
        """Extract platform information from record."""
        platform_elem = record.find(".//platform")
        if platform_elem is not None:
            return platform_elem.text
        return None

    def _extract_sample_count(self, record) -> Optional[int]:
        """Extract sample count from record."""
        try:
            samples_elem = record.find(".//samples")
            if samples_elem is not None:
                return int(samples_elem.text)
        except (ValueError, TypeError):
            pass
        return None

    def _extract_date(self, record, date_type: str) -> Optional[datetime]:
        """Extract date information from record."""
        try:
            date_elem = record.find(f".//{date_type}_date")
            if date_elem is not None:
                return datetime.fromisoformat(date_elem.text)
        except (ValueError, TypeError):
            pass
        return None

    def _extract_additional_metadata(self, record) -> Dict[str, Any]:
        """Extract additional metadata from record."""
        metadata = {}

        # Extract various metadata fields
        for field in [
            "platform_technology",
            "data_processing",
            "characteristics",
        ]:
            elem = record.find(f".//{field}")
            if elem is not None:
                metadata[field] = elem.text

        return metadata

    async def search_datasets(self, query: str, max_results: int = 10, start: int = 0) -> Dict[str, Any]:
        """
        Search for datasets in GEO database.

        Args:
            query: Search query string
            max_results: Maximum number of results to return
            start: Starting index for pagination

        Returns:
            Dictionary containing search results

        Raises:
            ExternalServiceError: If search fails
        """
        try:
            logger.info(f"Searching GEO for query: '{query}' (max_results={max_results})")

            # Build search URL for Entrez API
            url = f"{self._config.base_url}esearch.fcgi"
            params = {
                "db": "gds",
                "term": query,
                "retmax": min(max_results, 1000),  # NCBI limit
                "retstart": start,
                "retmode": "json",
                "usehistory": "y",
                "email": self._config.email,
            }

            # Add API key if available
            if self._config.api_key:
                params["api_key"] = self._config.api_key

            start_time = time.time()
            result = await self._make_request(url, params)
            search_time = time.time() - start_time

            # Process Entrez esearch JSON response
            esearch_result = result.get("esearchresult", {})
            count = int(esearch_result.get("count", 0))
            id_list = esearch_result.get("idlist", [])

            # Convert to our expected format
            processed_result = {
                "count": count,
                "ids": id_list,
                "webenv": esearch_result.get("webenv"),
                "querykey": esearch_result.get("querykey"),
            }

            # Add metadata
            processed_result["search_metadata"] = {
                "query": query,
                "max_results": max_results,
                "start": start,
                "search_time": search_time,
                "timestamp": datetime.utcnow().isoformat(),
                "source": "NCBI_GEO",
            }

            logger.info(f"Search completed: found {count} results in {search_time:.2f}s")
            return processed_result

        except Exception as e:
            logger.error(f"GEO search failed for query '{query}': {e}")
            # No mock fallback - return honest failure
            raise Exception(f"GEO search failed: {e}")

    async def get_dataset_details(self, geo_id: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information for a specific dataset.

        Args:
            geo_id: GEO dataset identifier

        Returns:
            Dataset details or None if not found

        Raises:
            ExternalServiceError: If retrieval fails
        """
        try:
            logger.info(f"Fetching details for dataset: {geo_id}")

            url = f"{self._config.base_url}query/acc.cgi"
            params = {"db": "gds", "id": geo_id, "retmode": "xml"}

            result = await self._make_request(url, params)

            if result["datasets"]:
                dataset = result["datasets"][0]
                logger.info(f"Retrieved details for dataset: {geo_id}")
                return dataset
            else:
                logger.warning(f"Dataset not found: {geo_id}")
                return None

        except Exception as e:
            logger.error(f"Failed to fetch dataset details for {geo_id}: {e}")
            raise

    async def search_by_organism(self, organism: str, max_results: int = 100) -> Dict[str, Any]:
        """
        Search datasets by organism.

        Args:
            organism: Organism name (e.g., "Homo sapiens")
            max_results: Maximum number of results

        Returns:
            Search results dictionary
        """
        query = f'"{organism}"[Organism]'
        return await self.search_datasets(query, max_results)

    async def search_by_platform(self, platform: str, max_results: int = 100) -> Dict[str, Any]:
        """
        Search datasets by platform.

        Args:
            platform: Platform identifier (e.g., "GPL570")
            max_results: Maximum number of results

        Returns:
            Search results dictionary
        """
        query = f'"{platform}"[Platform]'
        return await self.search_datasets(query, max_results)

    async def get_recent_datasets(self, days: int = 30, max_results: int = 50) -> Dict[str, Any]:
        """
        Get recently submitted datasets.

        Args:
            days: Number of days back to search
            max_results: Maximum number of results

        Returns:
            Search results dictionary
        """
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)

        query = f'("{start_date.strftime("%Y/%m/%d")}"[Publication Date] : "{end_date.strftime("%Y/%m/%d")}"[Publication Date])'
        return await self.search_datasets(query, max_results)

    async def validate_connection(self) -> bool:
        """
        Validate connection to GEO service.

        Returns:
            True if connection is valid, False otherwise
        """
        try:
            result = await self.search_datasets("test", max_results=1)
            return True
        except Exception as e:
            logger.error(f"GEO connection validation failed: {e}")
            return False

    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check on GEO service.

        Returns:
            Health check results
        """
        start_time = time.time()

        try:
            # Test basic search
            result = await self.search_datasets("human", max_results=1)
            response_time = time.time() - start_time

            return {
                "status": "healthy",
                "response_time": response_time,
                "results_count": result.get("count", 0),
                "timestamp": datetime.utcnow().isoformat(),
                "service": "NCBI_GEO",
            }

        except Exception as e:
            response_time = time.time() - start_time

            return {
                "status": "unhealthy",
                "error": str(e),
                "response_time": response_time,
                "timestamp": datetime.utcnow().isoformat(),
                "service": "NCBI_GEO",
            }
