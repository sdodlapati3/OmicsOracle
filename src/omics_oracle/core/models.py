"""
Core data models and types for OmicsOracle.

This module defines the fundamental data structures used throughout
the application for GEO data, search results, and API responses.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field
from pydantic import BaseModel, Field, validator


class AssayType(str, Enum):
    """Supported assay types."""

    RNA_SEQ = "RNA-seq"
    CHIP_SEQ = "ChIP-seq"
    ATAC_SEQ = "ATAC-seq"
    WGBS = "WGBS"
    RRBS = "RRBS"
    HISTONE_MARK = "Histone-mark"
    TRANSCRIPTION_FACTOR = "Transcription-factor"
    METHYLATION = "Methylation"
    OTHER = "Other"


class Organism(str, Enum):
    """Common organisms."""

    HUMAN = "Homo sapiens"
    MOUSE = "Mus musculus"
    RAT = "Rattus norvegicus"
    ARABIDOPSIS = "Arabidopsis thaliana"
    DROSOPHILA = "Drosophila melanogaster"
    YEAST = "Saccharomyces cerevisiae"
    OTHER = "Other"


class Platform(str, Enum):
    """Common sequencing platforms."""

    ILLUMINA_HISEQ = "Illumina HiSeq"
    ILLUMINA_NEXTSEQ = "Illumina NextSeq"
    ILLUMINA_NOVASEQ = "Illumina NovaSeq"
    AFFYMETRIX = "Affymetrix"
    AGILENT = "Agilent"
    OTHER = "Other"


@dataclass
class GEOSample:
    """Represents a GEO sample (GSM)."""

    accession: str
    title: str
    organism: str
    description: Optional[str] = None
    characteristics: Dict[str, str] = field(default_factory=dict)
    treatment: Optional[str] = None
    tissue: Optional[str] = None
    cell_type: Optional[str] = None
    platform: Optional[str] = None
    raw_data_available: bool = False

    def __post_init__(self) -> None:
        """Validate and normalize sample data."""
        self.accession = self.accession.upper()
        if not self.accession.startswith("GSM"):
            raise ValueError(f"Invalid GSM accession: {self.accession}")


@dataclass
class GEOSeries:
    """Represents a GEO series (GSE)."""

    accession: str
    title: str
    summary: str
    organism: str
    platform: str
    sample_count: int
    submission_date: Optional[datetime] = None
    publication_date: Optional[datetime] = None
    samples: List[GEOSample] = field(default_factory=list)
    assay_type: Optional[AssayType] = None
    pubmed_id: Optional[str] = None
    contact_name: Optional[str] = None
    contact_email: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate and normalize series data."""
        self.accession = self.accession.upper()
        if not self.accession.startswith("GSE"):
            raise ValueError(f"Invalid GSE accession: {self.accession}")


# Pydantic models for API requests/responses
class SearchRequest(BaseModel):
    """Search request model."""

    query: str = Field(..., min_length=3, max_length=500)
    filters: Optional[Dict[str, Any]] = None
    limit: int = Field(default=10, ge=1, le=100)
    offset: int = Field(default=0, ge=0)

    @validator("query")
    @classmethod
    def validate_query(cls, v: str) -> str:
        """Validate search query."""
        if not v.strip():
            raise ValueError("Query cannot be empty")
        return v.strip()


class SearchFilters(BaseModel):
    """Search filters model."""

    organism: Optional[List[str]] = None
    assay_type: Optional[List[AssayType]] = None
    platform: Optional[List[str]] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    min_samples: Optional[int] = Field(None, ge=1)
    max_samples: Optional[int] = Field(None, ge=1)

    @validator("max_samples")
    @classmethod
    def validate_sample_range(
        cls, v: Optional[int], values: Dict[str, Any]
    ) -> Optional[int]:
        """Validate sample count range."""
        if v is not None and "min_samples" in values and values["min_samples"]:
            if v < values["min_samples"]:
                raise ValueError("max_samples must be >= min_samples")
        return v


class GEOSeriesResponse(BaseModel):
    """GEO series response model."""

    accession: str
    title: str
    summary: str
    organism: str
    platform: str
    sample_count: int
    submission_date: Optional[datetime] = None
    publication_date: Optional[datetime] = None
    assay_type: Optional[AssayType] = None
    pubmed_id: Optional[str] = None

    class Config:
        """Pydantic configuration."""

        json_encoders = {datetime: lambda v: v.isoformat()}


class SearchResult(BaseModel):
    """Search result model."""

    total_count: int
    results: List[GEOSeriesResponse]
    query: str
    filters: Optional[SearchFilters] = None
    execution_time: float

    class Config:
        """Pydantic configuration."""

        json_encoders = {datetime: lambda v: v.isoformat()}


class ErrorResponse(BaseModel):
    """Error response model."""

    error: Dict[str, Any]

    @classmethod
    def from_exception(cls, exc: Exception) -> "ErrorResponse":
        """Create error response from exception."""
        error_data = {
            "code": exc.__class__.__name__.upper(),
            "message": str(exc),
        }

        # Add additional details if available
        if hasattr(exc, "code"):
            error_data["code"] = getattr(exc, "code")
        if hasattr(exc, "details"):
            error_data["details"] = getattr(exc, "details")

        return cls(error=error_data)


class HealthResponse(BaseModel):
    """Health check response model."""

    status: str
    timestamp: datetime
    version: str
    services: Dict[str, str]

    class Config:
        """Pydantic configuration."""

        json_encoders = {datetime: lambda v: v.isoformat()}


class MetadataExtract(BaseModel):
    """Extracted metadata model."""

    organism: Optional[str] = None
    assay_type: Optional[AssayType] = None
    tissue: Optional[str] = None
    cell_type: Optional[str] = None
    treatment: Optional[str] = None
    disease: Optional[str] = None
    platform: Optional[str] = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class NLPProcessingResult(BaseModel):
    """NLP processing result model."""

    original_query: str
    processed_query: str
    extracted_entities: List[str]
    metadata: MetadataExtract
    processing_time: float

    class Config:
        """Pydantic configuration."""

        json_encoders = {datetime: lambda v: v.isoformat()}
