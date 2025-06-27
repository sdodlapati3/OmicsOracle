"""
Simplified repository interface for Phase 3 implementation.

This interface defines the core contract for searching biomedical datasets
with a minimal set of required methods.
"""

from abc import ABC, abstractmethod
from typing import List, Optional

from ..entities.dataset import Dataset
from ..value_objects.search_query import SearchQuery


class SimpleSearchRepository(ABC):
    """Simplified abstract repository for dataset search operations."""

    @abstractmethod
    async def search(self, query: SearchQuery) -> List[Dataset]:
        """
        Search for datasets matching the query.

        Args:
            query: SearchQuery object containing search parameters

        Returns:
            List of Dataset objects matching the query

        Raises:
            SearchError: If search operation fails
        """
        pass

    @abstractmethod
    async def get_by_geo_id(self, geo_id: str) -> Optional[Dataset]:
        """
        Retrieve a specific dataset by GEO ID.

        Args:
            geo_id: The GEO identifier for the dataset

        Returns:
            Dataset object if found, None otherwise

        Raises:
            RepositoryError: If retrieval operation fails
        """
        pass

    @abstractmethod
    async def get_similar(
        self, dataset: Dataset, limit: int = 10
    ) -> List[Dataset]:
        """
        Find datasets similar to the given dataset.

        Args:
            dataset: Reference dataset for similarity search
            limit: Maximum number of similar datasets to return

        Returns:
            List of similar datasets

        Raises:
            RepositoryError: If similarity search fails
        """
        pass
