"""
Search-related Data Transfer Objects for OmicsOracle.

These DTOs handle data transfer for search operations between
the presentation layer and the application layer.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from ...domain.value_objects.search_query import SearchType, SortOrder


@dataclass
class SearchRequestDTO:
    """Data transfer object for search requests from the presentation layer."""

    # Required fields
    query: str

    # Optional search parameters
    max_results: int = 10
    search_type: SearchType = SearchType.COMPREHENSIVE
    sort_order: SortOrder = SortOrder.RELEVANCE

    # Filtering parameters
    organisms: Optional[List[str]] = None
    platforms: Optional[List[str]] = None
    min_samples: Optional[int] = None
    max_samples: Optional[int] = None
    date_from: Optional[str] = None  # ISO format date string
    date_to: Optional[str] = None  # ISO format date string

    # Advanced search parameters
    keywords: Optional[List[str]] = None
    exclude_keywords: Optional[List[str]] = None
    exact_match: bool = False
    include_supplementary: bool = True

    # Quality filters
    min_quality_score: Optional[float] = None
    require_complete_metadata: bool = False

    # Request metadata
    request_id: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None

    def __post_init__(self):
        """Validate search request after initialization."""
        if not self.query or not self.query.strip():
            raise ValueError("Query cannot be empty")

        if self.max_results <= 0 or self.max_results > 1000:
            raise ValueError("Max results must be between 1 and 1000")

        # Validate enum types if they're strings
        if isinstance(self.search_type, str):
            self.search_type = SearchType(self.search_type)

        if isinstance(self.sort_order, str):
            self.sort_order = SortOrder(self.sort_order)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SearchRequestDTO":
        """Create SearchRequestDTO from dictionary."""
        # Convert string enums to proper enum types
        if "search_type" in data and isinstance(data["search_type"], str):
            data["search_type"] = SearchType(data["search_type"])

        if "sort_order" in data and isinstance(data["sort_order"], str):
            data["sort_order"] = SortOrder(data["sort_order"])

        return cls(
            **{k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert SearchRequestDTO to dictionary."""
        return {
            "query": self.query,
            "max_results": self.max_results,
            "search_type": self.search_type.value,
            "sort_order": self.sort_order.value,
            "organisms": self.organisms,
            "platforms": self.platforms,
            "min_samples": self.min_samples,
            "max_samples": self.max_samples,
            "date_from": self.date_from,
            "date_to": self.date_to,
            "keywords": self.keywords,
            "exclude_keywords": self.exclude_keywords,
            "exact_match": self.exact_match,
            "include_supplementary": self.include_supplementary,
            "min_quality_score": self.min_quality_score,
            "require_complete_metadata": self.require_complete_metadata,
            "request_id": self.request_id,
            "user_id": self.user_id,
            "session_id": self.session_id,
        }


@dataclass
class DatasetDTO:
    """Data transfer object for dataset information."""

    # Core dataset information
    geo_id: str
    title: str
    summary: Optional[str] = None
    description: Optional[str] = None
    organism: Optional[str] = None
    platform: Optional[str] = None
    samples_count: Optional[int] = None
    series_count: Optional[int] = None

    # Date information as ISO strings
    submission_date: Optional[str] = None
    last_update_date: Optional[str] = None
    publication_date: Optional[str] = None

    # Additional metadata
    keywords: List[str] = field(default_factory=list)
    contact_info: Dict[str, str] = field(default_factory=dict)
    supplementary_files: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Quality metrics
    quality_score: Optional[float] = None
    completeness_score: Optional[float] = None
    relevance_score: Optional[float] = None

    # Computed properties
    is_valid: bool = True
    is_complete: bool = False
    sample_size_category: str = "unknown"

    @classmethod
    def from_dataset(
        cls, dataset, relevance_score: Optional[float] = None
    ) -> "DatasetDTO":
        """Create DatasetDTO from domain Dataset entity."""
        return cls(
            geo_id=dataset.geo_id,
            title=dataset.title,
            summary=dataset.summary,
            description=dataset.description,
            organism=dataset.organism,
            platform=dataset.platform,
            samples_count=dataset.samples_count,
            series_count=dataset.series_count,
            submission_date=dataset.submission_date.isoformat()
            if dataset.submission_date
            else None,
            last_update_date=dataset.last_update_date.isoformat()
            if dataset.last_update_date
            else None,
            publication_date=dataset.publication_date.isoformat()
            if dataset.publication_date
            else None,
            keywords=dataset.keywords.copy(),
            contact_info=dataset.contact_info.copy(),
            supplementary_files=dataset.supplementary_files.copy(),
            metadata=dataset.metadata.copy(),
            quality_score=dataset.quality_score,
            completeness_score=dataset.completeness_score,
            relevance_score=relevance_score,
            is_valid=dataset.is_valid,
            is_complete=dataset.is_complete,
            sample_size_category=dataset.sample_size_category,
        )


@dataclass
class SearchResponseDTO:
    """Data transfer object for search responses to the presentation layer."""

    # Core response data
    query: str
    datasets: List[DatasetDTO] = field(default_factory=list)
    total_found: int = 0
    total_returned: int = 0

    # Search metadata
    search_time: float = 0.0
    timestamp: str = field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )

    # Search parameters (for reference)
    max_results: int = 10
    search_type: str = SearchType.COMPREHENSIVE.value
    sort_order: str = SortOrder.RELEVANCE.value
    filters_applied: Dict[str, Any] = field(default_factory=dict)

    # Quality metrics
    average_relevance_score: float = 0.0
    average_quality_score: float = 0.0

    # Search source information
    sources_searched: List[str] = field(default_factory=list)
    source_response_times: Dict[str, float] = field(default_factory=dict)

    # Status information
    is_successful: bool = True
    has_results: bool = False
    completion_ratio: float = 1.0

    # Error and warning information
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    # Request tracking
    request_id: Optional[str] = None
    processing_id: Optional[str] = None

    def __post_init__(self):
        """Update computed fields after initialization."""
        self.total_returned = len(self.datasets)
        self.has_results = self.total_returned > 0

        if self.total_found > 0:
            self.completion_ratio = min(
                self.total_returned / self.total_found, 1.0
            )

        self.is_successful = len(self.errors) == 0 and self.has_results

        # Calculate average scores
        if self.datasets:
            relevance_scores = [
                d.relevance_score
                for d in self.datasets
                if d.relevance_score is not None
            ]
            quality_scores = [
                d.quality_score
                for d in self.datasets
                if d.quality_score is not None
            ]

            self.average_relevance_score = (
                sum(relevance_scores) / len(relevance_scores)
                if relevance_scores
                else 0.0
            )
            self.average_quality_score = (
                sum(quality_scores) / len(quality_scores)
                if quality_scores
                else 0.0
            )

    @classmethod
    def from_search_result(
        cls, search_result, request_dto: SearchRequestDTO
    ) -> "SearchResponseDTO":
        """Create SearchResponseDTO from domain SearchResult entity."""
        # Convert datasets to DTOs with relevance scores
        dataset_dtos = []
        for dataset in search_result.datasets:
            relevance_score = search_result.relevance_scores.get(dataset.geo_id)
            dataset_dto = DatasetDTO.from_dataset(dataset, relevance_score)
            dataset_dtos.append(dataset_dto)

        return cls(
            query=search_result.query,
            datasets=dataset_dtos,
            total_found=search_result.total_found,
            total_returned=search_result.total_returned,
            search_time=search_result.search_time,
            timestamp=search_result.timestamp.isoformat(),
            max_results=search_result.max_results,
            search_type=search_result.search_type,
            filters_applied=search_result.filters_applied.copy(),
            sources_searched=search_result.sources_searched.copy(),
            source_response_times=search_result.source_response_times.copy(),
            errors=search_result.errors.copy(),
            warnings=search_result.warnings.copy(),
            request_id=request_dto.request_id,
            processing_id=None,  # Will be set by use case
        )

    def add_processing_info(
        self, processing_id: str, additional_time: float = 0.0
    ) -> None:
        """Add processing information to the response."""
        self.processing_id = processing_id
        self.search_time += additional_time

    def add_error(self, error: str) -> None:
        """Add an error to the response."""
        if error not in self.errors:
            self.errors.append(error)
            self.is_successful = False

    def add_warning(self, warning: str) -> None:
        """Add a warning to the response."""
        if warning not in self.warnings:
            self.warnings.append(warning)

    def to_dict(self) -> Dict[str, Any]:
        """Convert SearchResponseDTO to dictionary."""
        return {
            "query": self.query,
            "datasets": [dataset.__dict__ for dataset in self.datasets],
            "total_found": self.total_found,
            "total_returned": self.total_returned,
            "search_time": self.search_time,
            "timestamp": self.timestamp,
            "max_results": self.max_results,
            "search_type": self.search_type,
            "sort_order": self.sort_order,
            "filters_applied": self.filters_applied,
            "average_relevance_score": self.average_relevance_score,
            "average_quality_score": self.average_quality_score,
            "sources_searched": self.sources_searched,
            "source_response_times": self.source_response_times,
            "is_successful": self.is_successful,
            "has_results": self.has_results,
            "completion_ratio": self.completion_ratio,
            "errors": self.errors,
            "warnings": self.warnings,
            "request_id": self.request_id,
            "processing_id": self.processing_id,
        }
