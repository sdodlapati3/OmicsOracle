"""
Search query value object representing search parameters.

This immutable value object encapsulates all parameters for a search operation,
ensuring validation and consistency across the application.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional


class SearchType(str, Enum):
    """Enumeration of supported search types."""

    COMPREHENSIVE = "comprehensive"
    TARGETED = "targeted"
    ADVANCED = "advanced"
    QUICK = "quick"


class SortOrder(str, Enum):
    """Enumeration of sort orders."""

    RELEVANCE = "relevance"
    DATE = "date"
    SAMPLES = "samples"
    TITLE = "title"


@dataclass(frozen=True)
class SearchQuery:
    """Immutable search query value object."""

    # Required parameters
    query_text: str

    # Optional parameters with defaults
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

    # Additional metadata
    search_id: Optional[str] = None
    user_preferences: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        """Validate search query parameters after initialization."""
        # Validate query text
        if not self.query_text or not self.query_text.strip():
            raise ValueError("Query text cannot be empty")

        if len(self.query_text) > 500:
            raise ValueError("Query text cannot exceed 500 characters")

        # Validate max_results
        if self.max_results <= 0:
            raise ValueError("Max results must be positive")

        if self.max_results > 1000:
            raise ValueError("Max results cannot exceed 1000")

        # Validate sample size constraints
        if self.min_samples is not None and self.min_samples < 0:
            raise ValueError("Minimum samples cannot be negative")

        if (
            self.min_samples is not None
            and self.max_samples is not None
            and self.min_samples > self.max_samples
        ):
            raise ValueError("Minimum samples cannot exceed maximum samples")

        # Validate quality score
        if self.min_quality_score is not None and (
            self.min_quality_score < 0.0 or self.min_quality_score > 1.0
        ):
            raise ValueError("Quality score must be between 0.0 and 1.0")

        # Validate date format (basic check)
        for date_str in [self.date_from, self.date_to]:
            if date_str and not self._is_valid_date_format(date_str):
                raise ValueError(
                    f"Invalid date format: {date_str}. Use YYYY-MM-DD format."
                )

    @staticmethod
    def _is_valid_date_format(date_str: str) -> bool:
        """Check if date string is in valid ISO format."""
        try:
            from datetime import datetime

            datetime.fromisoformat(date_str)
            return True
        except ValueError:
            return False

    @property
    def is_filtered(self) -> bool:
        """Check if the search query has any filters applied."""
        return any(
            [
                self.organisms,
                self.platforms,
                self.min_samples is not None,
                self.max_samples is not None,
                self.date_from,
                self.date_to,
                self.min_quality_score is not None,
                self.require_complete_metadata,
                self.exclude_keywords,
            ]
        )

    @property
    def is_advanced(self) -> bool:
        """Check if this is an advanced search query."""
        return (
            self.search_type == SearchType.ADVANCED
            or self.exact_match
            or bool(self.keywords)
            or bool(self.exclude_keywords)
            or self.is_filtered
        )

    @property
    def filter_count(self) -> int:
        """Count the number of filters applied."""
        filters = [
            bool(self.organisms),
            bool(self.platforms),
            self.min_samples is not None,
            self.max_samples is not None,
            bool(self.date_from),
            bool(self.date_to),
            self.min_quality_score is not None,
            self.require_complete_metadata,
            bool(self.exclude_keywords),
        ]
        return sum(filters)

    @property
    def normalized_query(self) -> str:
        """Get normalized version of the query text."""
        return self.query_text.strip().lower()

    def with_max_results(self, max_results: int) -> "SearchQuery":
        """Create a new SearchQuery with different max_results."""
        return SearchQuery(
            query_text=self.query_text,
            max_results=max_results,
            search_type=self.search_type,
            sort_order=self.sort_order,
            organisms=self.organisms,
            platforms=self.platforms,
            min_samples=self.min_samples,
            max_samples=self.max_samples,
            date_from=self.date_from,
            date_to=self.date_to,
            keywords=self.keywords,
            exclude_keywords=self.exclude_keywords,
            exact_match=self.exact_match,
            include_supplementary=self.include_supplementary,
            min_quality_score=self.min_quality_score,
            require_complete_metadata=self.require_complete_metadata,
            search_id=self.search_id,
            user_preferences=self.user_preferences,
        )

    def with_organism_filter(self, organisms: List[str]) -> "SearchQuery":
        """Create a new SearchQuery with organism filter."""
        return SearchQuery(
            query_text=self.query_text,
            max_results=self.max_results,
            search_type=self.search_type,
            sort_order=self.sort_order,
            organisms=organisms,
            platforms=self.platforms,
            min_samples=self.min_samples,
            max_samples=self.max_samples,
            date_from=self.date_from,
            date_to=self.date_to,
            keywords=self.keywords,
            exclude_keywords=self.exclude_keywords,
            exact_match=self.exact_match,
            include_supplementary=self.include_supplementary,
            min_quality_score=self.min_quality_score,
            require_complete_metadata=self.require_complete_metadata,
            search_id=self.search_id,
            user_preferences=self.user_preferences,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert search query to dictionary representation."""
        return {
            "query_text": self.query_text,
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
            "search_id": self.search_id,
            "user_preferences": self.user_preferences,
            "is_filtered": self.is_filtered,
            "is_advanced": self.is_advanced,
            "filter_count": self.filter_count,
            "normalized_query": self.normalized_query,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SearchQuery":
        """Create search query from dictionary representation."""
        # Convert enum strings back to enum values
        if "search_type" in data:
            data["search_type"] = SearchType(data["search_type"])
        if "sort_order" in data:
            data["sort_order"] = SortOrder(data["sort_order"])

        # Remove computed properties
        computed_props = [
            "is_filtered",
            "is_advanced",
            "filter_count",
            "normalized_query",
        ]
        for prop in computed_props:
            data.pop(prop, None)

        return cls(
            **{k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        )

    def __str__(self) -> str:
        """String representation of the search query."""
        filters_info = (
            f" ({self.filter_count} filters)" if self.is_filtered else ""
        )
        return f"SearchQuery('{self.query_text[:50]}...', max_results={self.max_results}{filters_info})"

    def __repr__(self) -> str:
        """Detailed string representation of the search query."""
        return (
            f"SearchQuery(query_text='{self.query_text}', max_results={self.max_results}, "
            f"search_type={self.search_type}, is_advanced={self.is_advanced})"
        )
