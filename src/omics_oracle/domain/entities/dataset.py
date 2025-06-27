"""
Core dataset entity representing a biomedical dataset.

This entity encapsulates all the essential information about a dataset
from various biomedical repositories like GEO, SRA, etc.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class Dataset:
    """Core dataset entity representing a biomedical dataset."""

    # Required fields
    geo_id: str
    title: str

    # Optional metadata
    summary: Optional[str] = None
    description: Optional[str] = None
    organism: Optional[str] = None
    platform: Optional[str] = None
    samples_count: Optional[int] = None
    series_count: Optional[int] = None

    # Dates
    submission_date: Optional[datetime] = None
    last_update_date: Optional[datetime] = None
    publication_date: Optional[datetime] = None

    # Additional metadata
    keywords: List[str] = field(default_factory=list)
    contact_info: Dict[str, str] = field(default_factory=dict)
    supplementary_files: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Quality indicators
    quality_score: Optional[float] = None
    completeness_score: Optional[float] = None

    def __post_init__(self):
        """Validate dataset after initialization."""
        if not self.geo_id:
            raise ValueError("GEO ID is required")
        if not self.title:
            raise ValueError("Title is required")

        # Normalize GEO ID format
        if not self.geo_id.startswith(("GSE", "GDS", "GPL", "GSM")):
            raise ValueError("Invalid GEO ID format")

    @property
    def is_valid(self) -> bool:
        """Check if dataset has minimum required information."""
        return bool(self.geo_id and self.title and len(self.title.strip()) > 0)

    @property
    def is_complete(self) -> bool:
        """Check if dataset has comprehensive information."""
        required_fields = [
            self.geo_id,
            self.title,
            self.summary,
            self.organism,
            self.platform,
        ]
        return all(field is not None for field in required_fields)

    @property
    def sample_size_category(self) -> str:
        """Categorize dataset by sample size."""
        if not self.samples_count:
            return "unknown"
        elif self.samples_count < 10:
            return "small"
        elif self.samples_count < 100:
            return "medium"
        else:
            return "large"

    def add_keyword(self, keyword: str) -> None:
        """Add a keyword to the dataset."""
        if keyword and keyword not in self.keywords:
            self.keywords.append(keyword.lower().strip())

    def add_metadata(self, key: str, value: Any) -> None:
        """Add metadata to the dataset."""
        if key:
            self.metadata[key] = value

    def get_metadata(self, key: str, default: Any = None) -> Any:
        """Get metadata value by key."""
        return self.metadata.get(key, default)

    def to_dict(self) -> Dict[str, Any]:
        """Convert dataset to dictionary representation."""
        return {
            "geo_id": self.geo_id,
            "title": self.title,
            "summary": self.summary,
            "description": self.description,
            "organism": self.organism,
            "platform": self.platform,
            "samples_count": self.samples_count,
            "series_count": self.series_count,
            "submission_date": self.submission_date.isoformat()
            if self.submission_date
            else None,
            "last_update_date": self.last_update_date.isoformat()
            if self.last_update_date
            else None,
            "publication_date": self.publication_date.isoformat()
            if self.publication_date
            else None,
            "keywords": self.keywords,
            "contact_info": self.contact_info,
            "supplementary_files": self.supplementary_files,
            "metadata": self.metadata,
            "quality_score": self.quality_score,
            "completeness_score": self.completeness_score,
            "is_valid": self.is_valid,
            "is_complete": self.is_complete,
            "sample_size_category": self.sample_size_category,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Dataset":
        """Create dataset from dictionary representation."""
        # Convert date strings back to datetime objects
        for date_field in [
            "submission_date",
            "last_update_date",
            "publication_date",
        ]:
            if data.get(date_field):
                data[date_field] = datetime.fromisoformat(data[date_field])

        return cls(
            **{k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        )

    def __str__(self) -> str:
        """String representation of the dataset."""
        return f"Dataset({self.geo_id}: {self.title[:50]}{'...' if len(self.title) > 50 else ''})"

    def __repr__(self) -> str:
        """Detailed string representation of the dataset."""
        return (
            f"Dataset(geo_id='{self.geo_id}', title='{self.title}', "
            f"organism='{self.organism}', samples={self.samples_count})"
        )
