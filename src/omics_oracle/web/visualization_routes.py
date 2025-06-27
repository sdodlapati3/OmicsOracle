"""
Visualization routes for OmicsOracle web interface.

This module provides API endpoints for data visualization and analytics.
"""

import logging
from collections import Counter
from typing import List

try:
    from fastapi import APIRouter, HTTPException
    from pydantic import BaseModel, Field

    FASTAPI_AVAILABLE = True
except ImportError:
    # Fallback for environments without FastAPI
    FASTAPI_AVAILABLE = False
    APIRouter = None
    HTTPException = None
    BaseModel = object
    Field = lambda *args, **kwargs: None

logger = logging.getLogger(__name__)

# Create visualization router
visualization_router = APIRouter()


class VisualizationStats(BaseModel):
    """Response model for visualization statistics."""

    total_datasets: int = Field(..., description="Total number of datasets")
    total_samples: int = Field(..., description="Total number of samples")
    unique_organisms: int = Field(..., description="Number of unique organisms")
    unique_platforms: int = Field(..., description="Number of unique platforms")
    avg_samples: int = Field(..., description="Average samples per dataset")
    date_range: str = Field(..., description="Publication date range")


class EntityDistribution(BaseModel):
    """Response model for entity distribution data."""

    labels: List[str] = Field(..., description="Entity type labels")
    counts: List[int] = Field(..., description="Count for each entity type")
    total_entities: int = Field(..., description="Total number of entities")


class OrganismDistribution(BaseModel):
    """Response model for organism distribution data."""

    labels: List[str] = Field(..., description="Organism names")
    counts: List[int] = Field(..., description="Count for each organism")
    colors: List[str] = Field(..., description="Chart colors for each organism")


class PlatformDistribution(BaseModel):
    """Response model for platform distribution data."""

    labels: List[str] = Field(..., description="Platform names")
    counts: List[int] = Field(..., description="Count for each platform")


class TimelineDistribution(BaseModel):
    """Response model for timeline distribution data."""

    years: List[str] = Field(..., description="Years")
    counts: List[int] = Field(..., description="Datasets per year")


class SearchVisualizationRequest(BaseModel):
    """Request model for search visualization."""

    query: str = Field(..., description="Search query")
    max_results: int = Field(
        default=50, ge=1, le=200, description="Maximum results for analysis"
    )


@visualization_router.post("/search-stats", response_model=VisualizationStats)
async def get_search_visualization_stats(request: SearchVisualizationRequest):
    """
    Get statistical overview for search results visualization.
    """
    try:
        # Import and initialize pipeline directly
        from omics_oracle.core.config import Config
        from omics_oracle.pipeline import OmicsOracle

        config = Config()
        pipeline = OmicsOracle(config)

        # Execute search to get data for visualization
        pipeline_result = await pipeline.search_datasets(
            query=request.query,
            max_results=request.max_results,
            include_sra=False,
        )

        metadata = pipeline_result.metadata or []

        # Calculate statistics
        total_datasets = len(metadata)
        total_samples = sum(
            int(d.get("sample_count", 0) or 0) for d in metadata
        )
        unique_organisms = len(
            set(
                d.get("organism", "Unknown")
                for d in metadata
                if d.get("organism")
            )
        )
        unique_platforms = len(
            set(
                d.get("platform", "Unknown")
                for d in metadata
                if d.get("platform")
            )
        )
        avg_samples = (
            int(total_samples / total_datasets) if total_datasets > 0 else 0
        )

        # Calculate date range
        dates = [
            d.get("publication_date", "")
            for d in metadata
            if d.get("publication_date")
        ]
        dates = [d for d in dates if d]  # Filter out empty dates
        if dates:
            dates.sort()
            date_range = f"{dates[0][:4]} - {dates[-1][:4]}"
        else:
            date_range = "N/A"

        return VisualizationStats(
            total_datasets=total_datasets,
            total_samples=total_samples,
            unique_organisms=unique_organisms,
            unique_platforms=unique_platforms,
            avg_samples=avg_samples,
            date_range=date_range,
        )

    except Exception as e:
        logger.error(f"Failed to get search visualization stats: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get visualization stats: {str(e)}",
        )


@visualization_router.post(
    "/entity-distribution", response_model=EntityDistribution
)
async def get_entity_distribution(request: SearchVisualizationRequest):
    """
    Get entity distribution data for visualization.
    """
    try:
        # Import and initialize pipeline directly
        from omics_oracle.core.config import Config
        from omics_oracle.pipeline import OmicsOracle

        config = Config()
        pipeline = OmicsOracle(config)

        # Execute search to get entities
        pipeline_result = await pipeline.search_datasets(
            query=request.query,
            max_results=request.max_results,
            include_sra=False,
        )

        entities = pipeline_result.entities or []

        if not entities:
            return EntityDistribution(labels=[], counts=[], total_entities=0)

        # Count entity types
        entity_counts = Counter()
        for entity in entities:
            if hasattr(entity, "label"):
                entity_counts[entity.label] += 1
            elif isinstance(entity, dict):
                entity_counts[entity.get("label", "OTHER")] += 1
            elif isinstance(entity, str):
                entity_counts[entity] += 1
            else:
                entity_counts["OTHER"] += 1

        # Sort by count and take top 10
        sorted_entities = entity_counts.most_common(10)

        return EntityDistribution(
            labels=[entity[0] for entity in sorted_entities],
            counts=[entity[1] for entity in sorted_entities],
            total_entities=sum(entity_counts.values()),
        )

    except Exception as e:
        logger.error(f"Failed to get entity distribution: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get entity distribution: {str(e)}",
        )


@visualization_router.post(
    "/organism-distribution", response_model=OrganismDistribution
)
async def get_organism_distribution(request: SearchVisualizationRequest):
    """
    Get organism distribution data for visualization.
    """
    try:
        # Import and initialize pipeline directly
        from omics_oracle.core.config import Config
        from omics_oracle.pipeline import OmicsOracle

        config = Config()
        pipeline = OmicsOracle(config)

        # Execute search to get data
        pipeline_result = await pipeline.search_datasets(
            query=request.query,
            max_results=request.max_results,
            include_sra=False,
        )

        metadata = pipeline_result.metadata or []

        # Count organisms
        organism_counts = Counter()
        for dataset in metadata:
            organism = dataset.get("organism", "Unknown")
            if organism:
                # Simplify organism names for display
                simplified = organism.replace("_", " ").title()
                organism_counts[simplified] += 1

        # Sort by count and take top 8
        sorted_organisms = organism_counts.most_common(8)

        # Define colors for organisms
        colors = [
            "#3498db",
            "#e74c3c",
            "#2ecc71",
            "#f39c12",
            "#9b59b6",
            "#1abc9c",
            "#34495e",
            "#e67e22",
        ]

        return OrganismDistribution(
            labels=[org[0] for org in sorted_organisms],
            counts=[org[1] for org in sorted_organisms],
            colors=colors[: len(sorted_organisms)],
        )

    except Exception as e:
        logger.error(f"Failed to get organism distribution: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get organism distribution: {str(e)}",
        )


@visualization_router.post(
    "/platform-distribution", response_model=PlatformDistribution
)
async def get_platform_distribution(request: SearchVisualizationRequest):
    """
    Get platform distribution data for visualization.
    """
    try:
        # Import and initialize pipeline directly
        from omics_oracle.core.config import Config
        from omics_oracle.pipeline import OmicsOracle

        config = Config()
        pipeline = OmicsOracle(config)

        # Execute search to get data
        pipeline_result = await pipeline.search_datasets(
            query=request.query,
            max_results=request.max_results,
            include_sra=False,
        )

        metadata = pipeline_result.metadata or []

        # Count platforms
        platform_counts = Counter()
        for dataset in metadata:
            platform = dataset.get("platform", "Unknown")
            if platform:
                # Simplify platform names - take first part before space
                simplified = platform.split(" ")[0] if platform else "Unknown"
                platform_counts[simplified] += 1

        # Sort by count and take top 10
        sorted_platforms = platform_counts.most_common(10)

        return PlatformDistribution(
            labels=[platform[0] for platform in sorted_platforms],
            counts=[platform[1] for platform in sorted_platforms],
        )

    except Exception as e:
        logger.error(f"Failed to get platform distribution: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get platform distribution: {str(e)}",
        )


@visualization_router.post(
    "/timeline-distribution", response_model=TimelineDistribution
)
async def get_timeline_distribution(request: SearchVisualizationRequest):
    """
    Get timeline distribution data for visualization.
    """
    try:
        # Import and initialize pipeline directly
        from omics_oracle.core.config import Config
        from omics_oracle.pipeline import OmicsOracle

        config = Config()
        pipeline = OmicsOracle(config)

        # Execute search to get data
        pipeline_result = await pipeline.search_datasets(
            query=request.query,
            max_results=request.max_results,
            include_sra=False,
        )

        metadata = pipeline_result.metadata or []

        # Count by year
        year_counts = Counter()
        for dataset in metadata:
            pub_date = dataset.get("publication_date", "")
            if pub_date and len(pub_date) >= 4:
                year = pub_date[:4]
                try:
                    # Validate year
                    int(year)
                    year_counts[year] += 1
                except ValueError:
                    continue

        if not year_counts:
            return TimelineDistribution(years=[], counts=[])

        # Sort by year
        sorted_years = sorted(year_counts.items())

        return TimelineDistribution(
            years=[year[0] for year in sorted_years],
            counts=[year[1] for year in sorted_years],
        )

    except Exception as e:
        logger.error(f"Failed to get timeline distribution: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get timeline distribution: {str(e)}",
        )


@visualization_router.get("/health")
async def visualization_health():
    """Health check for visualization endpoints."""
    return {
        "status": "healthy",
        "endpoints": [
            "/search-stats",
            "/entity-distribution",
            "/organism-distribution",
            "/platform-distribution",
            "/timeline-distribution",
        ],
    }
