"""
Pydantic models for the OmicsOracle web API.

This module defines request and response models for all API endpoints.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


class QueryStatus(str, Enum):
    """Query execution status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class OutputFormat(str, Enum):
    """Output format options."""

    JSON = "json"
    CSV = "csv"
    TSV = "tsv"
    SUMMARY = "summary"


class SearchRequest(BaseModel):
    """Request model for dataset search."""

    query: str = Field(..., description="Search query (natural language)")
    max_results: int = Field(default=10, ge=1, le=100, description="Maximum number of results")
    include_sra: bool = Field(default=False, description="Include SRA information")
    output_format: OutputFormat = Field(default=OutputFormat.JSON, description="Output format")

    # Advanced filter parameters
    organism: Optional[str] = Field(default=None, description="Organism filter (e.g., 'homo sapiens')")
    assay_type: Optional[str] = Field(default=None, description="Assay type filter (e.g., 'RNA-seq')")
    date_from: Optional[str] = Field(default=None, description="Start date filter (YYYY-MM-DD)")
    date_to: Optional[str] = Field(default=None, description="End date filter (YYYY-MM-DD)")

    @field_validator("query")
    @classmethod
    def query_must_not_be_empty(cls, v):
        """Validate query is not empty."""
        if not v.strip():
            raise ValueError("Query cannot be empty")
        return v.strip()


class DatasetInfoRequest(BaseModel):
    """Request model for dataset information."""

    dataset_id: str = Field(..., description="GEO dataset ID (e.g., GSE123456)")
    include_sra: bool = Field(default=False, description="Include SRA information")

    @field_validator("dataset_id")
    @classmethod
    def validate_dataset_id(cls, v):
        """Validate dataset ID format."""
        if not v.startswith(("GSE", "GDS", "GPL", "GSM")):
            raise ValueError("Invalid dataset ID format")
        return v.upper()


class AnalyzeRequest(BaseModel):
    """Request model for dataset analysis."""

    dataset_id: str = Field(..., description="GEO dataset ID")
    include_entity_linking: bool = Field(default=True, description="Include entity linking")
    output_format: OutputFormat = Field(default=OutputFormat.JSON, description="Output format")


class BatchRequest(BaseModel):
    """Request model for batch processing."""

    queries: List[str] = Field(..., description="List of search queries")
    max_results: int = Field(default=10, ge=1, le=100, description="Maximum results per query")
    output_format: OutputFormat = Field(default=OutputFormat.JSON, description="Output format")

    @field_validator("queries")
    @classmethod
    def validate_queries(cls, v):
        """Validate queries list."""
        if not v:
            raise ValueError("Queries list cannot be empty")
        if len(v) > 20:
            raise ValueError("Maximum 20 queries allowed per batch")
        return [q.strip() for q in v if q.strip()]


class ConfigRequest(BaseModel):
    """Request model for configuration updates."""

    key: str = Field(..., description="Configuration key")
    value: str = Field(..., description="Configuration value")


class EntityInfo(BaseModel):
    """Information about extracted entities."""

    text: str = Field(..., description="Entity text")
    label: str = Field(..., description="Entity type/label")
    confidence: Optional[float] = Field(None, description="Confidence score")
    start: Optional[int] = Field(None, description="Start position in text")
    end: Optional[int] = Field(None, description="End position in text")


class DatasetMetadata(BaseModel):
    """GEO dataset metadata."""

    id: str = Field(..., description="Dataset ID")
    title: str = Field(..., description="Dataset title")
    summary: str = Field(..., description="Dataset summary")
    organism: Optional[str] = Field(None, description="Organism")
    platform: Optional[str] = Field(None, description="Platform")
    sample_count: Optional[int] = Field(None, description="Number of samples")
    submission_date: Optional[str] = Field(None, description="Submission date")
    last_update_date: Optional[str] = Field(None, description="Last update date")
    pubmed_id: Optional[str] = Field(None, description="PubMed ID")
    sra_info: Optional[Dict[str, Any]] = Field(None, description="SRA information")


class SearchResult(BaseModel):
    """Search result containing metadata and analysis."""

    query_id: str = Field(..., description="Unique query ID")
    original_query: str = Field(..., description="Original search query")
    expanded_query: Optional[str] = Field(None, description="Expanded query")
    status: QueryStatus = Field(..., description="Query status")
    processing_time: Optional[float] = Field(None, description="Processing time (seconds)")
    entities: List[EntityInfo] = Field(default=[], description="Extracted entities")
    metadata: List[DatasetMetadata] = Field(default=[], description="Dataset metadata")
    ai_summaries: Optional[Dict[str, Any]] = Field(None, description="AI-generated summaries")
    error_message: Optional[str] = Field(None, description="Error message")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Creation timestamp")


class BatchResult(BaseModel):
    """Batch processing result."""

    batch_id: str = Field(..., description="Unique batch ID")
    total_queries: int = Field(..., description="Total number of queries")
    completed_queries: int = Field(default=0, description="Number of completed queries")
    failed_queries: int = Field(default=0, description="Number of failed queries")
    results: List[SearchResult] = Field(default=[], description="Individual query results")
    status: QueryStatus = Field(..., description="Overall batch status")
    started_at: datetime = Field(default_factory=datetime.utcnow, description="Batch start time")
    completed_at: Optional[datetime] = Field(None, description="Batch completion time")


class StatusResponse(BaseModel):
    """System status response."""

    status: str = Field(..., description="System status")
    configuration_loaded: bool = Field(..., description="Configuration status")
    ncbi_email: Optional[str] = Field(None, description="Configured NCBI email")
    pipeline_initialized: bool = Field(..., description="Pipeline status")
    active_queries: int = Field(default=0, description="Number of active queries")
    uptime: Optional[float] = Field(None, description="Server uptime")


class ConfigResponse(BaseModel):
    """Configuration response."""

    key: str = Field(..., description="Configuration key")
    value: str = Field(..., description="Configuration value")
    description: Optional[str] = Field(None, description="Key description")


class ErrorResponse(BaseModel):
    """Error response model."""

    error: str = Field(..., description="Error type")
    message: str = Field(..., description="Error message")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional details")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Error timestamp")


class WebSocketMessage(BaseModel):
    """WebSocket message model."""

    type: str = Field(..., description="Message type")
    query_id: Optional[str] = Field(None, description="Query ID")
    data: Dict[str, Any] = Field(..., description="Message data")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Message timestamp")


class AISummary(BaseModel):
    """AI-generated summary of a dataset."""

    overview: Optional[str] = Field(None, description="High-level overview")
    methodology: Optional[str] = Field(None, description="Methodology summary")
    significance: Optional[str] = Field(None, description="Research significance")
    technical_details: Optional[str] = Field(None, description="Technical details")
    brief: Optional[str] = Field(None, description="Brief summary")


class BatchAISummary(BaseModel):
    """AI-generated summary for batch results."""

    query: str = Field(..., description="Original query")
    total_datasets: int = Field(..., description="Total datasets found")
    total_samples: int = Field(..., description="Total samples across all datasets")
    organisms: List[str] = Field(default=[], description="List of organisms")
    platforms: List[str] = Field(default=[], description="List of platforms")
    study_types: List[str] = Field(default=[], description="List of study types")
    overview: str = Field(..., description="Batch overview summary")


class SummarizeRequest(BaseModel):
    """Request model for AI summarization."""

    query: str = Field(..., description="Search query (natural language)")
    max_results: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Maximum number of results to summarize",
    )
    summary_type: str = Field(
        default="comprehensive",
        description="Type of summary (brief, comprehensive, technical)",
    )
    include_individual: bool = Field(default=True, description="Include individual dataset summaries")

    # Advanced filter parameters (same as SearchRequest)
    organism: Optional[str] = Field(default=None, description="Organism filter (e.g., 'homo sapiens')")
    assay_type: Optional[str] = Field(default=None, description="Assay type filter (e.g., 'RNA-seq')")
    date_from: Optional[str] = Field(default=None, description="Start date filter (YYYY-MM-DD)")
    date_to: Optional[str] = Field(default=None, description="End date filter (YYYY-MM-DD)")

    @field_validator("query")
    @classmethod
    def query_must_not_be_empty(cls, v):
        """Validate query is not empty."""
        if not v.strip():
            raise ValueError("Query cannot be empty")
        return v.strip()

    @field_validator("summary_type")
    @classmethod
    def validate_summary_type(cls, v):
        """Validate summary type."""
        if v not in ["brief", "comprehensive", "technical"]:
            raise ValueError("Summary type must be one of: brief, comprehensive, technical")
        return v
