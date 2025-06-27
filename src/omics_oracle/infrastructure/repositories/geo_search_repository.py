"""
GEO search repository implementation.

This module provides a concrete implementation of the SearchRepository
using the NCBI GEO database API.
"""

import logging
from typing import List, Optional

from ...domain.entities.dataset import Dataset
from ...domain.repositories.simple_search_repository import (
    SimpleSearchRepository,
)
from ...domain.value_objects.search_query import SearchQuery
from ...shared.exceptions.domain_exceptions import (
    InfrastructureError,
    ValidationError,
)
from ..external_apis.geo_client import GEOClient

logger = logging.getLogger(__name__)


class GEOSearchRepository(SimpleSearchRepository):
    """Concrete implementation of search repository using GEO API."""

    def __init__(self, geo_client: GEOClient):
        """Initialize with a GEO client."""
        self._geo_client = geo_client

    async def search(self, query: SearchQuery) -> List[Dataset]:
        """Search datasets using GEO API."""
        try:
            logger.info(f"Searching GEO for: {query.query_text}")

            # Use the GEO client to search
            search_results = await self._geo_client.search_datasets(
                query=query.query_text,
                max_results=query.max_results,
                search_type=query.search_type.value
                if query.search_type
                else "all",
            )

            # Convert to domain entities
            datasets = []
            for result in search_results:
                try:
                    dataset = self._map_to_dataset(result)
                    datasets.append(dataset)
                except Exception as e:
                    logger.warning(f"Failed to map result to dataset: {e}")
                    continue

            logger.info(f"Found {len(datasets)} datasets")
            return datasets

        except Exception as e:
            logger.error(f"Search failed: {e}")
            raise InfrastructureError(f"GEO search failed: {str(e)}") from e

    async def get_by_geo_id(self, geo_id: str) -> Optional[Dataset]:
        """Retrieve a specific dataset by GEO ID."""
        try:
            if not geo_id:
                raise ValidationError("GEO ID cannot be empty")

            logger.info(f"Fetching dataset: {geo_id}")

            # Get detailed dataset information
            dataset_info = await self._geo_client.get_dataset_details(geo_id)

            if not dataset_info:
                return None

            return self._map_to_dataset(dataset_info)

        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to get dataset {geo_id}: {e}")
            raise InfrastructureError(
                f"Failed to retrieve dataset {geo_id}: {str(e)}"
            ) from e

    async def get_similar(
        self, dataset: Dataset, limit: int = 10
    ) -> List[Dataset]:
        """Find similar datasets based on metadata."""
        try:
            if not dataset or not dataset.geo_id:
                raise ValidationError("Dataset and GEO ID are required")

            logger.info(f"Finding similar datasets to: {dataset.geo_id}")

            # Use organism and platform for similarity search
            similarity_query = self._build_similarity_query(dataset)

            if not similarity_query:
                return []

            # Search for similar datasets
            search_query = SearchQuery(
                query_text=similarity_query,
                max_results=limit + 1,  # +1 to exclude the original
            )

            similar_datasets = await self.search(search_query)

            # Filter out the original dataset
            filtered_datasets = [
                d for d in similar_datasets if d.geo_id != dataset.geo_id
            ]

            return filtered_datasets[:limit]

        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Failed to find similar datasets: {e}")
            raise InfrastructureError(
                f"Failed to find similar datasets: {str(e)}"
            ) from e

    def _map_to_dataset(self, raw_result: dict) -> Dataset:
        """Map raw API result to domain entity."""
        try:
            return Dataset(
                geo_id=raw_result.get("geo_id", ""),
                title=raw_result.get("title", ""),
                summary=raw_result.get("summary"),
                organism=raw_result.get("organism"),
                platform=raw_result.get("platform"),
                samples_count=self._safe_int(raw_result.get("samples_count")),
                submission_date=raw_result.get("submission_date"),
                last_update_date=raw_result.get("last_update_date"),
                metadata=raw_result.get("metadata", {}),
            )
        except Exception as e:
            logger.error(f"Failed to map raw result to Dataset: {e}")
            raise InfrastructureError(f"Data mapping failed: {str(e)}") from e

    def _build_similarity_query(self, dataset: Dataset) -> str:
        """Build a search query to find similar datasets."""
        query_parts = []

        if dataset.organism:
            query_parts.append(f'"{dataset.organism}"[organism]')

        if dataset.platform:
            query_parts.append(f'"{dataset.platform}"[platform]')

        # Add general terms from title
        if dataset.title:
            # Extract key terms (simplified)
            title_words = dataset.title.lower().split()
            key_terms = [
                word
                for word in title_words
                if len(word) > 3
                and word not in {"with", "from", "study", "analysis"}
            ]
            if key_terms:
                query_parts.append(" OR ".join(key_terms[:3]))

        return " AND ".join(query_parts)

    def _safe_int(self, value) -> Optional[int]:
        """Safely convert value to int."""
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None
