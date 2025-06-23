"""
Unified GEO Client Interface

This module provides a unified interface to all GEO-related tools:
- entrezpy: NCBI E-utilities access
- GEOparse: GEO SOFT file parsing
- pysradb: SRA metadata retrieval
- geofetch: Standardized data download
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional

try:
    import entrezpy.conduit
    import entrezpy.esearch.esearcher

    HAS_ENTREZ = True
except ImportError:
    HAS_ENTREZ = False

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
from ..core.exceptions import (
    GEOClientError,
    GEOParseError,
    NCBIAPIError,
    SRAError,
)

logger = logging.getLogger(__name__)


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
        self._setup_clients()

    def _setup_clients(self) -> None:
        """Initialize all GEO tool clients."""
        if not HAS_ENTREZ:
            logger.warning("Entrez client not available")
            self.entrez_client = None
        else:
            # Initialize Entrez client for NCBI searches
            self.entrez_client = entrezpy.conduit.Conduit(
                self.config.ncbi.email,
                apikey=self.config.ncbi.api_key,
                threads=5,  # Default value
                qps=self.config.ncbi.rate_limit,
            )

        if not HAS_PYSRADB:
            logger.warning("SRA client not available")
            self.sra_client = None
        else:
            # Initialize SRA web client
            self.sra_client = SRAweb()

        logger.info("Unified GEO client initialized successfully")

    async def search_geo_series(
        self,
        query: str,
        max_results: int = 100,
    ) -> List[str]:
        """
        Search GEO database for series matching query.

        Args:
            query: Search query (e.g., 'breast cancer[All Fields]')
            max_results: Maximum number of results to return

        Returns:
            List of GEO series IDs (GSE numbers)
        """
        if not HAS_ENTREZ or self.entrez_client is None:
            raise GEOClientError("Entrez client not available")

        try:
            # Use entrezpy to search GEO database
            esearch = entrezpy.esearch.esearcher.Esearcher(
                tool="omics_oracle",
                email=self.config.ncbi.email,
                apikey=self.config.ncbi.api_key,
                qps=self.config.ncbi.rate_limit,
            )

            search_result = esearch.inquire(
                {
                    "db": "gds",
                    "term": query,
                    "retmax": max_results,
                    "usehistory": "y",
                }
            )

            if not search_result.get("esearchresult", {}).get("idlist"):
                logger.warning("No results found for query: %s", query)
                return []

            geo_ids = search_result["esearchresult"]["idlist"]
            logger.info(
                "Found %d GEO series for query: %s", len(geo_ids), query
            )

            return geo_ids

        except Exception as e:
            logger.error("Error searching GEO database: %s", str(e))
            raise NCBIAPIError(f"Failed to search GEO: {str(e)}") from e

    async def get_geo_metadata(
        self, geo_id: str, include_sra: bool = True
    ) -> Dict[str, Any]:
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

        try:
            logger.info("Retrieving metadata for %s", geo_id)

            # Parse GEO series using GEOparse
            gse = get_GEO(geo_id, destdir=str(self.config.cache.directory))

            # Extract basic metadata
            summary = getattr(gse, "metadata", {}).get("summary", [""])[0]
            metadata = {
                "geo_id": geo_id,
                "title": getattr(gse, "metadata", {}).get("title", [""])[0],
                "summary": summary,
                "overall_design": getattr(gse, "metadata", {}).get(
                    "overall_design", [""]
                )[0],
                "organism": getattr(gse, "metadata", {}).get("taxon", [""])[0],
                "submission_date": getattr(gse, "metadata", {}).get(
                    "submission_date", [""]
                )[0],
                "last_update_date": getattr(gse, "metadata", {}).get(
                    "last_update_date", [""]
                )[0],
                "contact_name": getattr(gse, "metadata", {}).get(
                    "contact_name", [""]
                ),
                "contact_email": getattr(gse, "metadata", {}).get(
                    "contact_email", [""]
                ),
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
                    logger.warning(
                        "Could not retrieve SRA data for %s: %s", geo_id, str(e)
                    )
                    metadata["sra_info"] = None

            logger.info("Successfully retrieved metadata for %s", geo_id)
            return metadata

        except Exception as e:
            logger.error("Error retrieving metadata for %s: %s", geo_id, str(e))
            raise GEOParseError(
                f"Failed to get metadata for {geo_id}: {str(e)}"
            ) from e

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
                "total_spots": df["total_spots"].sum()
                if "total_spots" in df
                else 0,
                "total_bases": df["total_bases"].sum()
                if "total_bases" in df
                else 0,
            }

            return sra_info

        except Exception as e:
            logger.debug(
                "SRA metadata not available for %s: %s", geo_id, str(e)
            )
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
                    logger.error(
                        "Failed to get metadata for %s: %s", geo_id, str(e)
                    )
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
            try:
                geo_id, metadata = result
                metadata_dict[geo_id] = metadata
            except (TypeError, ValueError) as e:
                logger.error("Invalid result format: %s", str(e))

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
            "entrez_api_key": "configured"
            if self.config.ncbi.api_key
            else "not_set",
            "cache_directory": str(self.config.cache.directory),
            "rate_limit": str(self.config.ncbi.rate_limit),
            "has_entrez": str(HAS_ENTREZ),
            "has_geoparse": str(HAS_GEOPARSE),
            "has_pysradb": str(HAS_PYSRADB),
        }
