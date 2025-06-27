"""
Search datasets use case.

This use case orchestrates the search for biomedical datasets,
handling validation, domain logic execution, and result formatting.
"""

import logging
import time
import uuid
from datetime import datetime
from typing import Optional

from ...domain.repositories.search_repository import SearchRepository
from ...domain.value_objects.search_query import SearchQuery
from ...shared.exceptions.domain_exceptions import (
    DomainError,
    SearchError,
    SearchTimeoutError,
    ValidationError,
)
from ..dto.search_dto import SearchRequestDTO, SearchResponseDTO

logger = logging.getLogger(__name__)


class SearchDatasetsUseCase:
    """
    Use case for searching biomedical datasets.

    This use case handles the complete search workflow:
    1. Validate search request
    2. Convert DTO to domain objects
    3. Execute search through repository
    4. Convert results back to DTOs
    5. Handle errors and logging
    """

    def __init__(self, search_repository: SearchRepository):
        """
        Initialize the search use case.

        Args:
            search_repository: Repository for dataset search operations
        """
        self._search_repository = search_repository

    async def execute(self, request: SearchRequestDTO) -> SearchResponseDTO:
        """
        Execute the search datasets use case.

        Args:
            request: Search request DTO from presentation layer

        Returns:
            Search response DTO with results and metadata

        Raises:
            ValidationError: If request validation fails
            SearchError: If search operation fails
            DomainError: For other domain-related errors
        """
        processing_id = str(uuid.uuid4())
        start_time = time.time()

        logger.info(
            f"Starting search use case execution - "
            f"processing_id: {processing_id}, "
            f"query: '{request.query}', "
            f"max_results: {request.max_results}"
        )

        try:
            # Step 1: Validate request
            self._validate_request(request)

            # Step 2: Convert DTO to domain object
            search_query = self._convert_to_domain_query(request)

            # Step 3: Execute search through repository
            search_result = await self._execute_search(search_query)

            # Step 4: Convert result to DTO
            response = SearchResponseDTO.from_search_result(
                search_result, request
            )

            # Step 5: Add processing metadata
            processing_time = time.time() - start_time
            response.add_processing_info(processing_id, processing_time)

            logger.info(
                f"Search use case completed successfully - "
                f"processing_id: {processing_id}, "
                f"results: {response.total_returned}/{response.total_found}, "
                f"time: {processing_time:.3f}s"
            )

            return response

        except ValidationError as e:
            logger.warning(
                f"Search validation failed - "
                f"processing_id: {processing_id}, "
                f"error: {e.message}"
            )
            return self._create_error_response(
                request, processing_id, str(e), start_time
            )

        except SearchTimeoutError as e:
            logger.warning(
                f"Search timed out - "
                f"processing_id: {processing_id}, "
                f"timeout: {e.timeout_seconds}s"
            )
            return self._create_error_response(
                request, processing_id, str(e), start_time
            )

        except SearchError as e:
            logger.error(
                f"Search error occurred - "
                f"processing_id: {processing_id}, "
                f"error: {e.message}, "
                f"source: {e.source}"
            )
            return self._create_error_response(
                request, processing_id, str(e), start_time
            )

        except DomainError as e:
            logger.error(
                f"Domain error in search use case - "
                f"processing_id: {processing_id}, "
                f"error: {e.message}"
            )
            return self._create_error_response(
                request, processing_id, str(e), start_time
            )

        except Exception as e:
            logger.error(
                f"Unexpected error in search use case - "
                f"processing_id: {processing_id}, "
                f"error: {str(e)}"
            )
            return self._create_error_response(
                request,
                processing_id,
                "An unexpected error occurred during search",
                start_time,
            )

    def _validate_request(self, request: SearchRequestDTO) -> None:
        """
        Validate the search request.

        Args:
            request: Search request to validate

        Raises:
            ValidationError: If validation fails
        """
        if not request.query or not request.query.strip():
            raise ValidationError("Search query cannot be empty", field="query")

        if len(request.query) > 500:
            raise ValidationError(
                "Search query cannot exceed 500 characters",
                field="query",
                value=len(request.query),
            )

        if request.max_results <= 0 or request.max_results > 1000:
            raise ValidationError(
                "Max results must be between 1 and 1000",
                field="max_results",
                value=request.max_results,
            )

        # Validate sample size constraints
        if (
            request.min_samples is not None
            and request.max_samples is not None
            and request.min_samples > request.max_samples
        ):
            raise ValidationError(
                "Minimum samples cannot exceed maximum samples",
                field="sample_constraints",
                details={
                    "min_samples": request.min_samples,
                    "max_samples": request.max_samples,
                },
            )

        # Validate quality score
        if request.min_quality_score is not None and (
            request.min_quality_score < 0.0 or request.min_quality_score > 1.0
        ):
            raise ValidationError(
                "Quality score must be between 0.0 and 1.0",
                field="min_quality_score",
                value=request.min_quality_score,
            )

    def _convert_to_domain_query(
        self, request: SearchRequestDTO
    ) -> SearchQuery:
        """
        Convert search request DTO to domain SearchQuery.

        Args:
            request: Search request DTO

        Returns:
            Domain SearchQuery object

        Raises:
            ValidationError: If conversion fails due to invalid data
        """
        try:
            return SearchQuery(
                query_text=request.query.strip(),
                max_results=request.max_results,
                search_type=request.search_type,
                sort_order=request.sort_order,
                organisms=request.organisms,
                platforms=request.platforms,
                min_samples=request.min_samples,
                max_samples=request.max_samples,
                date_from=request.date_from,
                date_to=request.date_to,
                keywords=request.keywords,
                exclude_keywords=request.exclude_keywords,
                exact_match=request.exact_match,
                include_supplementary=request.include_supplementary,
                min_quality_score=request.min_quality_score,
                require_complete_metadata=request.require_complete_metadata,
                search_id=request.request_id,
                user_preferences={
                    "user_id": request.user_id,
                    "session_id": request.session_id,
                },
            )
        except ValueError as e:
            raise ValidationError(f"Invalid search parameters: {str(e)}")

    async def _execute_search(self, search_query: SearchQuery):
        """
        Execute the search through the repository.

        Args:
            search_query: Domain SearchQuery object

        Returns:
            SearchResult from repository

        Raises:
            SearchError: If search execution fails
        """
        try:
            return await self._search_repository.search(search_query)
        except Exception as e:
            raise SearchError(
                f"Search execution failed: {str(e)}",
                query=search_query.query_text,
                source="repository",
            )

    def _create_error_response(
        self,
        request: SearchRequestDTO,
        processing_id: str,
        error_message: str,
        start_time: float,
    ) -> SearchResponseDTO:
        """
        Create an error response DTO.

        Args:
            request: Original search request
            processing_id: Processing ID for tracking
            error_message: Error message to include
            start_time: Start time for duration calculation

        Returns:
            SearchResponseDTO with error information
        """
        processing_time = time.time() - start_time

        response = SearchResponseDTO(
            query=request.query,
            datasets=[],
            total_found=0,
            total_returned=0,
            search_time=processing_time,
            timestamp=datetime.utcnow().isoformat(),
            max_results=request.max_results,
            search_type=request.search_type.value,
            sort_order=request.sort_order.value,
            errors=[error_message],
            is_successful=False,
            has_results=False,
            request_id=request.request_id,
            processing_id=processing_id,
        )

        return response


class GetDatasetDetailsUseCase:
    """
    Use case for retrieving detailed information about a specific dataset.
    """

    def __init__(self, search_repository: SearchRepository):
        """
        Initialize the get dataset details use case.

        Args:
            search_repository: Repository for dataset operations
        """
        self._search_repository = search_repository

    async def execute(self, geo_id: str) -> Optional[SearchResponseDTO]:
        """
        Execute the get dataset details use case.

        Args:
            geo_id: GEO ID of the dataset to retrieve

        Returns:
            SearchResponseDTO with single dataset or None if not found

        Raises:
            ValidationError: If GEO ID is invalid
            DomainError: For other domain-related errors
        """
        processing_id = str(uuid.uuid4())
        start_time = time.time()

        logger.info(
            f"Starting get dataset details use case - "
            f"processing_id: {processing_id}, "
            f"geo_id: {geo_id}"
        )

        try:
            # Validate GEO ID
            if not geo_id or not geo_id.strip():
                raise ValidationError("GEO ID cannot be empty", field="geo_id")

            if not geo_id.startswith(("GSE", "GDS", "GPL", "GSM")):
                raise ValidationError(
                    f"Invalid GEO ID format: {geo_id}", field="geo_id"
                )

            # Retrieve dataset
            dataset = await self._search_repository.get_by_geo_id(
                geo_id.strip()
            )

            if dataset is None:
                logger.info(f"Dataset not found - geo_id: {geo_id}")
                return None

            # Create response with single dataset
            processing_time = time.time() - start_time

            from ..dto.search_dto import DatasetDTO

            dataset_dto = DatasetDTO.from_dataset(dataset)

            response = SearchResponseDTO(
                query=f"GEO ID: {geo_id}",
                datasets=[dataset_dto],
                total_found=1,
                total_returned=1,
                search_time=processing_time,
                timestamp=datetime.utcnow().isoformat(),
                max_results=1,
                search_type="direct",
                is_successful=True,
                has_results=True,
                processing_id=processing_id,
            )

            logger.info(
                f"Get dataset details completed - "
                f"processing_id: {processing_id}, "
                f"found: {dataset is not None}, "
                f"time: {processing_time:.3f}s"
            )

            return response

        except Exception as e:
            logger.error(
                f"Error in get dataset details use case - "
                f"processing_id: {processing_id}, "
                f"geo_id: {geo_id}, "
                f"error: {str(e)}"
            )
            raise
