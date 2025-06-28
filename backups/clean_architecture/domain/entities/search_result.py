"""
Search result entity representing the outcome of a search operation.

This entity encapsulates the results of a search query along with
metadata about the search operation itself.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from .dataset import Dataset


@dataclass
class SearchResult:
    """Search result entity containing datasets and search metadata."""

    # Core search information
    query: str
    datasets: List[Dataset] = field(default_factory=list)

    # Search metadata
    total_found: int = 0
    total_returned: int = 0
    search_time: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)

    # Search parameters
    max_results: int = 10
    search_type: str = "comprehensive"
    filters_applied: Dict[str, Any] = field(default_factory=dict)

    # Quality metrics
    relevance_scores: Dict[str, float] = field(default_factory=dict)
    quality_scores: Dict[str, float] = field(default_factory=dict)

    # Search source information
    sources_searched: List[str] = field(default_factory=list)
    source_response_times: Dict[str, float] = field(default_factory=dict)

    # Error information
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def __post_init__(self):
        """Validate search result after initialization."""
        if not self.query:
            raise ValueError("Search query is required")

        # Update total_returned based on actual datasets
        self.total_returned = len(self.datasets)

        # Ensure total_found is at least total_returned
        if self.total_found < self.total_returned:
            self.total_found = self.total_returned

    @property
    def is_successful(self) -> bool:
        """Check if search was successful."""
        return len(self.errors) == 0 and self.total_returned > 0

    @property
    def has_results(self) -> bool:
        """Check if search returned any results."""
        return self.total_returned > 0

    @property
    def completion_ratio(self) -> float:
        """Calculate the ratio of returned results to total found."""
        if self.total_found == 0:
            return 1.0
        return min(self.total_returned / self.total_found, 1.0)

    @property
    def average_relevance_score(self) -> float:
        """Calculate average relevance score of results."""
        if not self.relevance_scores:
            return 0.0
        return sum(self.relevance_scores.values()) / len(self.relevance_scores)

    @property
    def average_quality_score(self) -> float:
        """Calculate average quality score of results."""
        if not self.quality_scores:
            return 0.0
        return sum(self.quality_scores.values()) / len(self.quality_scores)

    def add_dataset(
        self,
        dataset: Dataset,
        relevance_score: Optional[float] = None,
        quality_score: Optional[float] = None,
    ) -> None:
        """Add a dataset to the search results."""
        if dataset not in self.datasets:
            self.datasets.append(dataset)

            if relevance_score is not None:
                self.relevance_scores[dataset.geo_id] = relevance_score

            if quality_score is not None:
                self.quality_scores[dataset.geo_id] = quality_score

            # Update totals
            self.total_returned = len(self.datasets)
            if self.total_found < self.total_returned:
                self.total_found = self.total_returned

    def remove_dataset(self, geo_id: str) -> bool:
        """Remove a dataset from the search results by GEO ID."""
        for i, dataset in enumerate(self.datasets):
            if dataset.geo_id == geo_id:
                self.datasets.pop(i)
                self.relevance_scores.pop(geo_id, None)
                self.quality_scores.pop(geo_id, None)
                self.total_returned = len(self.datasets)
                return True
        return False

    def get_dataset_by_id(self, geo_id: str) -> Optional[Dataset]:
        """Get a dataset by its GEO ID."""
        for dataset in self.datasets:
            if dataset.geo_id == geo_id:
                return dataset
        return None

    def sort_by_relevance(self, descending: bool = True) -> None:
        """Sort datasets by relevance score."""

        def relevance_key(dataset):
            return self.relevance_scores.get(dataset.geo_id, 0.0)

        self.datasets.sort(key=relevance_key, reverse=descending)

    def sort_by_quality(self, descending: bool = True) -> None:
        """Sort datasets by quality score."""

        def quality_key(dataset):
            return self.quality_scores.get(dataset.geo_id, 0.0)

        self.datasets.sort(key=quality_key, reverse=descending)

    def sort_by_date(self, descending: bool = True) -> None:
        """Sort datasets by submission date."""

        def date_key(dataset):
            return dataset.submission_date or datetime.min

        self.datasets.sort(key=date_key, reverse=descending)

    def filter_by_organism(self, organism: str) -> "SearchResult":
        """Create a new SearchResult filtered by organism."""
        filtered_datasets = [
            dataset
            for dataset in self.datasets
            if dataset.organism and organism.lower() in dataset.organism.lower()
        ]

        return SearchResult(
            query=f"{self.query} (filtered by {organism})",
            datasets=filtered_datasets,
            total_found=len(filtered_datasets),
            total_returned=len(filtered_datasets),
            search_time=self.search_time,
            timestamp=self.timestamp,
            max_results=self.max_results,
            search_type=self.search_type,
            filters_applied={**self.filters_applied, "organism": organism},
            sources_searched=self.sources_searched,
        )

    def filter_by_sample_size(
        self, min_samples: int = 0, max_samples: Optional[int] = None
    ) -> "SearchResult":
        """Create a new SearchResult filtered by sample size."""
        filtered_datasets = []
        for dataset in self.datasets:
            if dataset.samples_count is None:
                continue
            if dataset.samples_count >= min_samples:
                if max_samples is None or dataset.samples_count <= max_samples:
                    filtered_datasets.append(dataset)

        filter_desc = f"samples >= {min_samples}"
        if max_samples:
            filter_desc += f" and <= {max_samples}"

        return SearchResult(
            query=f"{self.query} (filtered by {filter_desc})",
            datasets=filtered_datasets,
            total_found=len(filtered_datasets),
            total_returned=len(filtered_datasets),
            search_time=self.search_time,
            timestamp=self.timestamp,
            max_results=self.max_results,
            search_type=self.search_type,
            filters_applied={
                **self.filters_applied,
                "sample_size": {"min": min_samples, "max": max_samples},
            },
            sources_searched=self.sources_searched,
        )

    def add_error(self, error: str) -> None:
        """Add an error message to the search result."""
        if error not in self.errors:
            self.errors.append(error)

    def add_warning(self, warning: str) -> None:
        """Add a warning message to the search result."""
        if warning not in self.warnings:
            self.warnings.append(warning)

    def to_dict(self) -> Dict[str, Any]:
        """Convert search result to dictionary representation."""
        return {
            "query": self.query,
            "datasets": [dataset.to_dict() for dataset in self.datasets],
            "total_found": self.total_found,
            "total_returned": self.total_returned,
            "search_time": self.search_time,
            "timestamp": self.timestamp.isoformat(),
            "max_results": self.max_results,
            "search_type": self.search_type,
            "filters_applied": self.filters_applied,
            "relevance_scores": self.relevance_scores,
            "quality_scores": self.quality_scores,
            "sources_searched": self.sources_searched,
            "source_response_times": self.source_response_times,
            "errors": self.errors,
            "warnings": self.warnings,
            "is_successful": self.is_successful,
            "has_results": self.has_results,
            "completion_ratio": self.completion_ratio,
            "average_relevance_score": self.average_relevance_score,
            "average_quality_score": self.average_quality_score,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SearchResult":
        """Create search result from dictionary representation."""
        # Convert timestamp string back to datetime
        if "timestamp" in data:
            data["timestamp"] = datetime.fromisoformat(data["timestamp"])

        # Convert dataset dictionaries back to Dataset objects
        if "datasets" in data:
            data["datasets"] = [Dataset.from_dict(dataset_data) for dataset_data in data["datasets"]]

        # Remove computed properties
        computed_props = [
            "is_successful",
            "has_results",
            "completion_ratio",
            "average_relevance_score",
            "average_quality_score",
        ]
        for prop in computed_props:
            data.pop(prop, None)

        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def __str__(self) -> str:
        """String representation of the search result."""
        return f"SearchResult(query='{self.query}', results={self.total_returned}/{self.total_found})"

    def __repr__(self) -> str:
        """Detailed string representation of the search result."""
        return (
            f"SearchResult(query='{self.query}', datasets={len(self.datasets)}, "
            f"search_time={self.search_time:.3f}s, successful={self.is_successful})"
        )
