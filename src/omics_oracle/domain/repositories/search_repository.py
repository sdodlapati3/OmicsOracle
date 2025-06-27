"""
Abstract repository interface for dataset search operations.

This interface defines the contract for searching and retrieving biomedical datasets
from various sources while maintaining independence from specific implementations.
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from ..entities.dataset import Dataset
from ..entities.search_result import SearchResult
from ..value_objects.search_query import SearchQuery


class SearchRepository(ABC):
    """Abstract repository for dataset search operations."""
    
    @abstractmethod
    async def search(self, query: SearchQuery) -> SearchResult:
        """
        Search for datasets matching the query.
        
        Args:
            query: SearchQuery object containing search parameters
            
        Returns:
            SearchResult containing matching datasets and metadata
            
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
    async def get_similar(self, dataset: Dataset, limit: int = 10) -> List[Dataset]:
        """
        Find datasets similar to the given dataset.
        
        Args:
            dataset: Reference dataset for similarity comparison
            limit: Maximum number of similar datasets to return
            
        Returns:
            List of similar Dataset objects
            
        Raises:
            RepositoryError: If similarity search fails
        """
        pass
    
    @abstractmethod
    async def get_by_keywords(self, keywords: List[str], limit: int = 100) -> List[Dataset]:
        """
        Search datasets by specific keywords.
        
        Args:
            keywords: List of keywords to search for
            limit: Maximum number of datasets to return
            
        Returns:
            List of Dataset objects matching the keywords
            
        Raises:
            RepositoryError: If keyword search fails
        """
        pass
    
    @abstractmethod
    async def get_by_organism(self, organism: str, limit: int = 100) -> List[Dataset]:
        """
        Search datasets by organism.
        
        Args:
            organism: Organism name to search for
            limit: Maximum number of datasets to return
            
        Returns:
            List of Dataset objects for the specified organism
            
        Raises:
            RepositoryError: If organism search fails
        """
        pass
    
    @abstractmethod
    async def get_by_platform(self, platform: str, limit: int = 100) -> List[Dataset]:
        """
        Search datasets by platform.
        
        Args:
            platform: Platform name to search for
            limit: Maximum number of datasets to return
            
        Returns:
            List of Dataset objects using the specified platform
            
        Raises:
            RepositoryError: If platform search fails
        """
        pass
    
    @abstractmethod
    async def get_recent(self, days: int = 30, limit: int = 50) -> List[Dataset]:
        """
        Get recently submitted datasets.
        
        Args:
            days: Number of days back to search
            limit: Maximum number of datasets to return
            
        Returns:
            List of recently submitted Dataset objects
            
        Raises:
            RepositoryError: If recent search fails
        """
        pass
    
    @abstractmethod
    async def get_popular(self, limit: int = 50) -> List[Dataset]:
        """
        Get popular/highly cited datasets.
        
        Args:
            limit: Maximum number of datasets to return
            
        Returns:
            List of popular Dataset objects
            
        Raises:
            RepositoryError: If popularity search fails
        """
        pass
    
    @abstractmethod
    async def count_by_organism(self) -> Dict[str, int]:
        """
        Get count of datasets by organism.
        
        Returns:
            Dictionary mapping organism names to dataset counts
            
        Raises:
            RepositoryError: If count operation fails
        """
        pass
    
    @abstractmethod
    async def count_by_platform(self) -> Dict[str, int]:
        """
        Get count of datasets by platform.
        
        Returns:
            Dictionary mapping platform names to dataset counts
            
        Raises:
            RepositoryError: If count operation fails
        """
        pass
    
    @abstractmethod
    async def get_statistics(self) -> Dict[str, Any]:
        """
        Get repository statistics.
        
        Returns:
            Dictionary containing various repository statistics
            
        Raises:
            RepositoryError: If statistics retrieval fails
        """
        pass
    
    @abstractmethod
    async def validate_connection(self) -> bool:
        """
        Validate repository connection.
        
        Returns:
            True if connection is valid, False otherwise
        """
        pass
    
    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check on the repository.
        
        Returns:
            Dictionary containing health status information
        """
        pass
