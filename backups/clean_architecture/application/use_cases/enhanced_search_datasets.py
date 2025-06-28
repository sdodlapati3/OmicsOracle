"""
Enhanced search datasets use case with event publishing.

This module implements the core business logic for searching
biomedical datasets with event-driven architecture support.
"""

import logging
from datetime import datetime
from typing import Optional

from ...domain.repositories.simple_search_repository import SimpleSearchRepository
from ...domain.value_objects.search_query import SearchQuery
from ...services.ai_summary_manager import ai_summary_manager
from ...shared.exceptions.domain_exceptions import ValidationError
from ..dto.search_dto import DatasetDTO, SearchRequestDTO, SearchResponseDTO

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
                from ...infrastructure.messaging.search_events import SearchStartedEvent

                await self._event_bus.publish(
                    SearchStartedEvent(
                        query=request.query,
                        search_type=request.search_type.value if request.search_type else "all",
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
                # Calculate relevance score based on query matching
                relevance_score = self._calculate_relevance_score(request.query, dataset)

                # Generate AI summary using centralized manager
                ai_summary = ai_summary_manager.generate_ai_summary(
                    request.query, dataset.__dict__, dataset.geo_id
                )

                # Use the proper DatasetDTO conversion
                dataset_dto = DatasetDTO.from_dataset(
                    dataset, relevance_score=relevance_score, ai_summary=ai_summary
                )
                result_dtos.append(dataset_dto)

            logger.info(f"Search completed: found {len(datasets)} datasets in {search_duration:.2f}s")

            # Publish search completed event
            if self._event_bus:
                from ...infrastructure.messaging.search_events import SearchCompletedEvent

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
                from ...infrastructure.messaging.search_events import SearchFailedEvent

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
                from ...infrastructure.messaging.search_events import SearchFailedEvent

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

    def _calculate_relevance_score(self, query: str, dataset) -> float:
        """
        Calculate relevance score based on query term matching.

        Args:
            query: The search query
            dataset: The dataset object

        Returns:
            Float between 0.0 and 1.0 representing relevance
        """
        import re

        # Normalize query terms
        query_terms = [term.lower().strip() for term in re.split(r"[,\s]+", query) if term.strip()]
        if not query_terms:
            return 0.0

        score = 0.0
        max_possible_score = 0.0

        # Get text fields with weights
        fields_and_weights = [
            (dataset.title or "", 3.0),  # Title matches are most important
            (dataset.summary or "", 2.0),  # Summary matches are important
            (dataset.description or "", 1.5),  # Description matches are moderately important
            (" ".join(dataset.keywords or []), 1.0),  # Keyword matches are least important
            (dataset.organism or "", 0.8),  # Organism matches are relevant
        ]

        for text_field, weight in fields_and_weights:
            text_lower = text_field.lower()
            max_possible_score += weight

            # Count matching terms
            matching_terms = 0
            for term in query_terms:
                if term in text_lower:
                    matching_terms += 1

            # Calculate partial score for this field
            if query_terms:
                field_score = (matching_terms / len(query_terms)) * weight
                score += field_score

        # Normalize to 0-1 range
        if max_possible_score > 0:
            normalized_score = score / max_possible_score
        else:
            normalized_score = 0.0

        # Ensure score is within 0-1 range
        final_score = max(0.0, min(1.0, normalized_score))

        return round(final_score, 2)
