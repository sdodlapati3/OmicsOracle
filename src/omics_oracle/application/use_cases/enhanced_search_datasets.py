"""
Enhanced search datasets use case with event publishing.

This module implements the core business logic for searching
biomedical datasets with event-driven architecture support.
"""

import logging
from datetime import datetime
from typing import Optional

from ...domain.repositories.simple_search_repository import (
    SimpleSearchRepository,
)
from ...domain.value_objects.search_query import SearchQuery
from ...shared.exceptions.domain_exceptions import ValidationError
from ..dto.search_dto import SearchRequestDTO, SearchResponseDTO

logger = logging.getLogger(__name__)


class EnhancedSearchDatasetsUseCase:
    """Enhanced use case for searching biomedical datasets with events."""

    def __init__(
        self,
        search_repository: SimpleSearchRepository,
        event_bus: Optional[object] = None,
    ):
        """Initialize the use case with required dependencies."""
        self._search_repository = search_repository
        self._event_bus = event_bus

    async def execute(self, request: SearchRequestDTO) -> SearchResponseDTO:
        """Execute the search datasets use case with event publishing."""
        start_time = datetime.now()

        try:
            # Validate input
            if not request.query or not request.query.strip():
                raise ValidationError("Search query cannot be empty")

            logger.info(f"Executing search for: {request.query}")

            # Publish search started event
            if self._event_bus:
                from ...infrastructure.messaging.search_events import (
                    SearchStartedEvent,
                )

                await self._event_bus.publish(
                    SearchStartedEvent(
                        query=request.query,
                        search_type=request.search_type.value
                        if request.search_type
                        else "all",
                        max_results=request.max_results,
                        timestamp=start_time,
                    )
                )

            # Convert DTO to domain object
            search_query = SearchQuery(
                query_text=request.query.strip(),
                max_results=request.max_results,
                search_type=request.search_type,
                sort_order=request.sort_order,
            )

            # Execute search through repository
            datasets = await self._search_repository.search(search_query)

            # Calculate search duration
            search_duration = (datetime.now() - start_time).total_seconds()

            # Convert domain entities to DTOs
            result_dtos = []
            for dataset in datasets:
                result_dtos.append(
                    {
                        "geo_id": dataset.geo_id,
                        "title": dataset.title,
                        "summary": dataset.summary,
                        "organism": dataset.organism,
                        "platform": dataset.platform,
                        "samples_count": dataset.samples_count,
                        "submission_date": dataset.submission_date.isoformat()
                        if dataset.submission_date
                        else None,
                        "last_update_date": dataset.last_update_date.isoformat()
                        if dataset.last_update_date
                        else None,
                        "metadata": dataset.metadata or {},
                    }
                )

            logger.info(
                f"Search completed: found {len(datasets)} datasets in {search_duration:.2f}s"
            )

            # Publish search completed event
            if self._event_bus:
                from ...infrastructure.messaging.search_events import (
                    SearchCompletedEvent,
                )

                await self._event_bus.publish(
                    SearchCompletedEvent(
                        query=request.query,
                        results_count=len(datasets),
                        search_duration=search_duration,
                        timestamp=datetime.now(),
                    )
                )

            return SearchResponseDTO(
                query=request.query,
                datasets=result_dtos,
                total_found=len(datasets),
                search_time=search_duration,
                timestamp=datetime.now().isoformat(),
            )

        except ValidationError:
            # Publish search failed event
            if self._event_bus:
                search_duration = (datetime.now() - start_time).total_seconds()
                from ...infrastructure.messaging.search_events import (
                    SearchFailedEvent,
                )

                await self._event_bus.publish(
                    SearchFailedEvent(
                        query=request.query,
                        error_message="Invalid search query",
                        error_type="ValidationError",
                        search_duration=search_duration,
                        timestamp=datetime.now(),
                    )
                )
            raise
        except Exception as e:
            search_duration = (datetime.now() - start_time).total_seconds()
            logger.error(f"Search failed after {search_duration:.2f}s: {e}")

            # Publish search failed event
            if self._event_bus:
                from ...infrastructure.messaging.search_events import (
                    SearchFailedEvent,
                )

                await self._event_bus.publish(
                    SearchFailedEvent(
                        query=request.query,
                        error_message=str(e),
                        error_type=type(e).__name__,
                        search_duration=search_duration,
                        timestamp=datetime.now(),
                    )
                )
            raise
