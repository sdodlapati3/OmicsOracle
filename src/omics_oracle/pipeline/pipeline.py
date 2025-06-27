"""
Core Pipeline Implementation for OmicsOracle

This module provides the main OmicsOracle class that orchestrates the entire
pipeline from natural language query to biological data retrieval and analysis.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional

from ..core.config import Config
from ..core.exceptions import OmicsOracleException
from ..geo_tools.geo_client import UnifiedGEOClient
from ..nlp.biomedical_ner import BiomedicalNER, EnhancedBiologicalSynonymMapper
from ..nlp.prompt_interpreter import PromptInterpreter
from ..services.improved_search import ImprovedSearchService
from ..services.summarizer import SummarizationService

logger = logging.getLogger(__name__)


class QueryStatus(Enum):
    """Status of query processing."""

    PENDING = "pending"
    PARSING = "parsing"
    SEARCHING = "searching"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class ResultFormat(Enum):
    """Supported result formats."""

    JSON = "json"
    CSV = "csv"
    TSV = "tsv"
    EXCEL = "excel"
    SUMMARY = "summary"


@dataclass
class ProgressEvent:
    """Event for tracking progress of a pipeline operation."""

    stage: str
    message: str
    percentage: float = 0.0
    detail: Optional[Dict[str, Any]] = None
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class QueryResult:
    """Result of a query processing pipeline."""

    query_id: str
    original_query: str
    status: QueryStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    intent: Optional[str] = None
    entities: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    expanded_query: Optional[str] = None
    geo_ids: List[str] = field(default_factory=list)
    metadata: List[Dict[str, Any]] = field(default_factory=list)
    ai_summaries: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    processing_steps: List[Dict[str, Any]] = field(default_factory=list)
    progress_events: List[ProgressEvent] = field(default_factory=list)

    @property
    def duration(self) -> Optional[float]:
        """Get processing duration in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None

    @property
    def is_completed(self) -> bool:
        """Check if query processing is completed."""
        return self.status == QueryStatus.COMPLETED

    @property
    def is_failed(self) -> bool:
        """Check if query processing failed."""
        return self.status == QueryStatus.FAILED

    def add_step(self, step_name: str, details: Dict[str, Any]) -> None:
        """Add a processing step to the result."""
        self.processing_steps.append(
            {
                "step": step_name,
                "timestamp": datetime.now(),
                "details": details,
            }
        )

    def add_progress_event(self, event: ProgressEvent) -> None:
        """Add a progress event to the result."""
        self.progress_events.append(event)


class OmicsOracle:
    """
    Main pipeline class that orchestrates biological data search and analysis.

    This class integrates natural language processing, GEO database search,
    and data processing to provide a comprehensive biological data analysis
    pipeline.
    """

    def __init__(self, config: Optional[Config] = None, disable_cache: bool = True):
        """
        Initialize OmicsOracle pipeline.

        Args:
            config: Configuration object. If None, loads from default sources.
            disable_cache: Whether to disable caching for search results and metadata
        """
        self.config = config or Config()
        self.disable_cache = disable_cache
        self._setup_logging()

        # Initialize components
        self.geo_client = UnifiedGEOClient(self.config)

        # Disable caching if requested
        if self.disable_cache:
            if hasattr(self.geo_client, "cache"):
                logger.info("Disabling GEO client cache as requested")
                self.geo_client.cache = None

        self.nlp_interpreter = PromptInterpreter()
        self.biomedical_ner = BiomedicalNER()
        self.synonym_mapper = EnhancedBiologicalSynonymMapper()
        self.summarizer = SummarizationService(self.config, disable_cache=self.disable_cache)

        # Initialize improved search service
        self.search_service = ImprovedSearchService(
            self.geo_client, self.biomedical_ner, self.synonym_mapper
        )

        # Pipeline state
        self._active_queries: Dict[str, QueryResult] = {}
        self._query_counter = 0

        # Progress reporting callback
        self._progress_callback: Optional[
            Callable[[str, ProgressEvent], Awaitable[None]]
        ] = None

        logger.info("OmicsOracle pipeline initialized successfully")

    def _setup_logging(self) -> None:
        """Set up logging configuration."""
        logging.basicConfig(
            level=getattr(logging, self.config.logging.level.upper()),
            format=self.config.logging.format,
        )

    def set_progress_callback(
        self, callback: Callable[[str, ProgressEvent], Awaitable[None]]
    ) -> None:
        """Set callback for progress events."""
        self._progress_callback = callback

    def _generate_query_id(self) -> str:
        """Generate a unique query ID."""
        self._query_counter += 1
        return f"query_{self._query_counter:06d}"

    async def _report_progress(
        self,
        result: QueryResult,
        stage: str,
        message: str,
        percentage: float = 0.0,
        detail: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Report progress for a query."""
        event = ProgressEvent(
            stage=stage,
            message=message,
            percentage=percentage,
            detail=detail,
        )

        # Add to query result
        result.add_progress_event(event)

        # Call callback if set
        if self._progress_callback:
            try:
                await self._progress_callback(result.query_id, event)
            except Exception as e:
                logger.error(f"Error in progress callback: {e}")

    async def process_query(
        self,
        query: str,
        max_results: int = 100,
        include_sra: bool = False,
        result_format: ResultFormat = ResultFormat.JSON,
    ) -> QueryResult:
        """
        Process a natural language query through the complete pipeline.

        Args:
            query: Natural language query
            max_results: Maximum number of results to return
            include_sra: Whether to include SRA metadata
            result_format: Format for results

        Returns:
            QueryResult object with processing results

        Raises:
            OmicsOracleError: If pipeline processing fails
        """
        query_id = self._generate_query_id()
        result = QueryResult(
            query_id=query_id,
            original_query=query,
            status=QueryStatus.PENDING,
            start_time=datetime.now(),
        )
        self._active_queries[query_id] = result

        logger.info("Starting query processing: %s", query_id)
        result.add_step(
            "initialization", {"query": query, "query_id": query_id}
        )

        await self._report_progress(
            result,
            "initialization",
            "Initializing query processing",
            0.0,
            {"query": query},
        )

        try:
            # Step 1: Parse natural language query (10% of progress)
            result.status = QueryStatus.PARSING
            await self._report_progress(
                result,
                "parsing",
                "Analyzing your query and extracting key biomedical concepts",
                5.0,
            )
            await self._parse_query(result)
            await self._report_progress(
                result,
                "parsing_complete",
                "Query analysis complete",
                10.0,
                {"intent": result.intent, "entities": result.entities},
            )

            # Step 2: Search for relevant GEO data (40% of progress)
            result.status = QueryStatus.SEARCHING
            await self._report_progress(
                result,
                "searching",
                "Searching NCBI GEO database for relevant datasets",
                15.0,
            )
            await self._search_geo_data(result, max_results)

            geo_count = len(result.geo_ids)
            await self._report_progress(
                result,
                "search_complete",
                f"Search complete - found {geo_count} relevant datasets",
                40.0,
                {"geo_count": geo_count},
            )

            # Step 3: Process and enhance results (40% of progress)
            result.status = QueryStatus.PROCESSING

            if result.geo_ids:
                # Process metadata in batches with progress updates
                await self._process_results_with_progress(result, include_sra)
            else:
                await self._report_progress(
                    result, "processing", "No datasets found to process", 80.0
                )

            # Step 4: Format results (10% of progress)
            await self._report_progress(
                result, "formatting", "Formatting and finalizing results", 90.0
            )
            await self._format_results(result, result_format)

            result.status = QueryStatus.COMPLETED
            result.end_time = datetime.now()

            await self._report_progress(
                result,
                "complete",
                f"Query processing complete in {result.duration:.2f}s",
                100.0,
                {"duration": result.duration},
            )

            logger.info(
                "Query processing completed: %s (duration: %.2fs)",
                query_id,
                result.duration,
            )

        except Exception as e:
            result.status = QueryStatus.FAILED
            result.error = str(e)
            result.end_time = datetime.now()

            await self._report_progress(
                result, "error", f"Error: {str(e)}", 100.0, {"error": str(e)}
            )

            logger.error("Query processing failed: %s - %s", query_id, str(e))
            raise OmicsOracleException(
                f"Pipeline processing failed: {str(e)}"
            ) from e

        return result

    async def _parse_query(self, result: QueryResult) -> None:
        """Parse natural language query and extract entities."""
        logger.debug("Parsing query: %s", result.query_id)

        # Extract intent using prompt interpreter
        await self._report_progress(
            result, "intent_extraction", "Determining search intent", 6.0
        )

        intent_result = self.nlp_interpreter.classify_intent(
            result.original_query
        )
        result.intent = intent_result.get("intent")

        result.add_step(
            "intent_classification",
            {
                "intent": result.intent,
                "confidence": intent_result.get("confidence"),
            },
        )

        await self._report_progress(
            result,
            "entity_extraction",
            "Extracting biomedical entities from query",
            8.0,
        )

        # Initial entity extraction (will be enhanced during search)
        entities = self.biomedical_ner.extract_biomedical_entities(
            result.original_query
        )
        result.entities = entities

        result.add_step("entity_extraction", {"entities": entities})

        # Basic query expansion for compatibility
        result.expanded_query = result.original_query

        logger.debug("Query parsing completed for: %s", result.query_id)

    async def _search_geo_data(
        self, result: QueryResult, max_results: int
    ) -> None:
        """Search GEO database for relevant data using improved search."""
        logger.debug("Searching GEO data: %s", result.query_id)

        try:
            # Use improved search service for better results
            await self._report_progress(
                result,
                "search_strategy",
                "Applying multiple search strategies for optimal results",
                20.0,
            )

            # Progress updates for search strategies
            progress_base = 20.0
            progress_increment = 15.0

            def search_progress_callback(strategy_index, strategy_name, status):
                progress = min(
                    progress_base + (progress_increment * (strategy_index / 3)),
                    35.0,
                )
                asyncio.create_task(
                    self._report_progress(
                        result,
                        f"search_strategy_{strategy_index}",
                        f"Using search strategy: {strategy_name} - {status}",
                        progress,
                        {"strategy": strategy_name, "status": status},
                    )
                )

            # Add progress callback to search service if available
            if hasattr(self.search_service, "set_progress_callback"):
                self.search_service.set_progress_callback(
                    search_progress_callback
                )

            # Execute search
            (
                geo_ids,
                search_metadata,
            ) = await self.search_service.search_with_multiple_strategies(
                result.original_query, max_results=max_results
            )

            result.geo_ids = geo_ids
            result.expanded_query = search_metadata.get(
                "original_query", result.original_query
            )

            # Update entities with enhanced extraction
            if "enhanced_entities" in search_metadata:
                result.entities = search_metadata["enhanced_entities"]

            result.add_step(
                "improved_geo_search",
                {
                    "original_query": result.original_query,
                    "strategies_tried": search_metadata.get(
                        "strategies_tried", 0
                    ),
                    "successful_strategies": search_metadata.get(
                        "successful_strategies", 0
                    ),
                    "strategy_details": search_metadata.get(
                        "strategy_details", {}
                    ),
                    "geo_ids": geo_ids,
                    "count": len(geo_ids),
                },
            )

            logger.debug(
                "Improved GEO search completed: %s (found %d results using %d strategies)",
                result.query_id,
                len(geo_ids),
                search_metadata.get("successful_strategies", 0),
            )

        except Exception as e:
            logger.error(
                "Improved GEO search failed: %s - %s", result.query_id, str(e)
            )
            result.add_step("geo_search_error", {"error": str(e)})
            # Continue with empty results rather than failing completely
            result.geo_ids = []

    async def _process_results(
        self, result: QueryResult, include_sra: bool
    ) -> None:
        """Process and enhance search results."""
        logger.debug("Processing results: %s", result.query_id)

        metadata_list = []

        # Process each GEO ID - no artificial limit
        for geo_id in result.geo_ids:
            try:
                metadata = await self.geo_client.get_geo_metadata(
                    geo_id, include_sra=include_sra
                )
                if metadata:
                    # Enhance metadata with relevance scoring
                    enhanced_metadata = await self._enhance_metadata(
                        metadata, result
                    )
                    
                    # Only add if the enhanced metadata has a relevance score
                    # and it's greater than a minimum threshold
                    if enhanced_metadata.get("relevance_score", 0) > 0.1:
                        metadata_list.append(enhanced_metadata)
                    else:
                        logger.debug(
                            "Skipping %s due to low relevance score: %s", 
                            geo_id, 
                            enhanced_metadata.get("relevance_score", 0)
                        )

            except Exception as e:
                logger.warning(
                    "Failed to get metadata for %s: %s", geo_id, str(e)
                )
                continue

        result.metadata = metadata_list

        # Generate AI summaries for the results
        await self._generate_ai_summaries(result)

        result.add_step(
            "metadata_processing",
            {
                "processed_count": len(metadata_list),
                "total_geo_ids": len(result.geo_ids),
                "ai_summaries_generated": bool(result.ai_summaries),
            },
        )

        logger.debug(
            "Results processing completed: %s (processed %d items)",
            result.query_id,
            len(metadata_list),
        )

    async def _process_results_with_progress(
        self, result: QueryResult, include_sra: bool
    ) -> None:
        """Process results with detailed progress reporting."""
        logger.debug(
            "Processing results with progress tracking: %s", result.query_id
        )

        metadata_list = []
        total_ids = len(result.geo_ids)  # Process all results, no artificial limit

        await self._report_progress(
            result,
            "metadata_extraction",
            f"Extracting metadata from {total_ids} datasets",
            45.0,
            {"total_datasets": total_ids},
        )

        # Process each GEO ID with progress updates
        for i, geo_id in enumerate(result.geo_ids):
            progress_percentage = 45.0 + ((i / total_ids) * 25.0)  # 45% to 70%

            await self._report_progress(
                result,
                "processing_dataset",
                f"Retrieving metadata for dataset {i+1}/{total_ids}: {geo_id}",
                progress_percentage,
                {"current": i + 1, "total": total_ids, "geo_id": geo_id},
            )

            try:
                metadata = await self.geo_client.get_geo_metadata(
                    geo_id, include_sra=include_sra
                )
                if metadata:
                    # Enhance metadata with relevance scoring
                    enhanced_metadata = await self._enhance_metadata(
                        metadata, result
                    )
                    
                    # Only include results with sufficient relevance
                    if enhanced_metadata.get("relevance_score", 0) > 0.1:
                        metadata_list.append(enhanced_metadata)

                        # Report success for this dataset
                        await self._report_progress(
                            result,
                            "dataset_processed",
                            f"Successfully processed dataset {geo_id}",
                            progress_percentage,
                            {
                                "geo_id": geo_id,
                                "title": metadata.get("title", "Unknown title"),
                                "organism": metadata.get(
                                    "organism", "Unknown organism"
                                ),
                                "samples": metadata.get("sample_count", 0),
                                "relevance_score": enhanced_metadata.get("relevance_score", 0),
                            },
                        )
                    else:
                        await self._report_progress(
                            result,
                            "dataset_skipped",
                            f"Skipping dataset {geo_id} due to low relevance score: {enhanced_metadata.get('relevance_score', 0)}",
                            progress_percentage,
                            {"geo_id": geo_id, "reason": "low_relevance", "score": enhanced_metadata.get("relevance_score", 0)},
                        )
                else:
                    await self._report_progress(
                        result,
                        "dataset_skipped",
                        f"No metadata available for dataset {geo_id}",
                        progress_percentage,
                        {"geo_id": geo_id, "reason": "no_metadata"},
                    )

            except Exception as e:
                logger.warning(
                    "Failed to get metadata for %s: %s", geo_id, str(e)
                )

                await self._report_progress(
                    result,
                    "dataset_error",
                    f"Error processing dataset {geo_id}: {str(e)}",
                    progress_percentage,
                    {"geo_id": geo_id, "error": str(e)},
                )
                continue

        result.metadata = metadata_list

        # AI summary generation (70% to 90%)
        await self._report_progress(
            result,
            "ai_summarization",
            "Generating AI insights and analysis",
            75.0,
            {"datasets_to_analyze": len(metadata_list)},
        )

        # Generate AI summaries for the results
        await self._generate_ai_summaries_with_progress(result)

        result.add_step(
            "metadata_processing",
            {
                "processed_count": len(metadata_list),
                "total_geo_ids": len(result.geo_ids),
                "ai_summaries_generated": bool(result.ai_summaries),
            },
        )

        logger.debug(
            "Results processing completed: %s (processed %d items)",
            result.query_id,
            len(metadata_list),
        )

    async def _enhance_metadata(
        self, metadata: Dict[str, Any], result: QueryResult
    ) -> Dict[str, Any]:
        """Enhance metadata with relevance scoring and entity matching."""
        enhanced = metadata.copy()

        # Calculate relevance score based on entity matches
        relevance_score = 0.0
        matched_entities = []

        # Check title and summary for entity matches
        text_content = (
            metadata.get("title", "") + " " + metadata.get("summary", "")
        ).lower()

        for entity_type, entity_list in result.entities.items():
            for entity in entity_list:
                entity_text = entity["text"].lower()
                if entity_text in text_content:
                    relevance_score += 1.0
                    matched_entities.append(
                        {"type": entity_type, "text": entity_text}
                    )

                # Check synonyms too
                synonyms = self.synonym_mapper.get_synonyms(
                    entity_text, entity_type
                )
                for synonym in synonyms:
                    if synonym.lower() in text_content:
                        relevance_score += 0.5
                        matched_entities.append(
                            {
                                "type": entity_type,
                                "text": synonym,
                                "original": entity_text,
                            }
                        )

        enhanced["relevance_score"] = relevance_score
        enhanced["matched_entities"] = matched_entities

        return enhanced

    async def _format_results(
        self, result: QueryResult, result_format: ResultFormat
    ) -> None:
        """Format results according to specified format."""
        logger.debug("Formatting results: %s", result.query_id)

        # Sort results by relevance score
        if result.metadata:
            result.metadata.sort(
                key=lambda x: x.get("relevance_score", 0), reverse=True
            )

        result.add_step(
            "result_formatting",
            {
                "format": result_format.value,
                "sorted_by_relevance": True,
                "result_count": len(result.metadata),
            },
        )

    async def get_query_status(self, query_id: str) -> Optional[QueryResult]:
        """Get the status of a query by ID."""
        return self._active_queries.get(query_id)

    async def list_active_queries(self) -> List[str]:
        """List all active query IDs."""
        return list(self._active_queries.keys())

    async def cancel_query(self, query_id: str) -> bool:
        """Cancel an active query."""
        if query_id in self._active_queries:
            result = self._active_queries[query_id]
            if result.status not in [QueryStatus.COMPLETED, QueryStatus.FAILED]:
                result.status = QueryStatus.FAILED
                result.error = "Query cancelled by user"
                result.end_time = datetime.now()

                await self._report_progress(
                    result, "cancelled", "Query cancelled by user", 100.0
                )

                return True
        return False

    async def cleanup_completed_queries(self, max_age_hours: int = 24) -> int:
        """Clean up completed queries older than specified hours."""
        current_time = datetime.now()
        cleaned_count = 0

        for query_id, result in list(self._active_queries.items()):
            if result.end_time:
                age_hours = (
                    current_time - result.end_time
                ).total_seconds() / 3600
                if age_hours > max_age_hours:
                    del self._active_queries[query_id]
                    cleaned_count += 1

        logger.info("Cleaned up %d completed queries", cleaned_count)
        return cleaned_count

    async def close(self) -> None:
        """Clean up resources."""
        await self.geo_client.close()
        logger.info("OmicsOracle pipeline closed")

    async def _generate_ai_summaries(self, result: QueryResult) -> None:
        """Generate AI-powered summaries for the query results."""
        logger.debug("Generating AI summaries: %s", result.query_id)

        if not result.metadata:
            logger.debug("No metadata available for summarization")
            return

        try:
            # Generate batch summary for all results
            batch_summary = self.summarizer.summarize_batch_results(
                [{"metadata": metadata} for metadata in result.metadata],
                result.original_query,
            )
            result.ai_summaries["batch_summary"] = batch_summary

            # Generate individual summaries for top results (limit to 5 for performance)
            top_results = result.metadata[:5]
            individual_summaries = []

            for metadata in top_results:
                try:
                    # Generate comprehensive summary for each dataset
                    summary = self.summarizer.summarize_dataset(
                        metadata,
                        query_context=result.original_query,
                        summary_type="comprehensive",
                    )
                    individual_summaries.append(
                        {
                            "accession": metadata.get("accession", "Unknown"),
                            "summary": summary,
                        }
                    )
                except Exception as e:
                    logger.warning(
                        "Failed to summarize dataset %s: %s",
                        metadata.get("accession", "Unknown"),
                        str(e),
                    )
                    continue

            result.ai_summaries["individual_summaries"] = individual_summaries

            # Generate a brief overall summary
            if len(result.metadata) > 0:
                first_result = result.metadata[0]
                brief_summary = self.summarizer.summarize_dataset(
                    first_result,
                    query_context=result.original_query,
                    summary_type="brief",
                )
                result.ai_summaries["brief_overview"] = brief_summary

            logger.debug(
                "AI summaries generated successfully: %s", result.query_id
            )

        except Exception as e:
            logger.error(
                "Failed to generate AI summaries: %s - %s",
                result.query_id,
                str(e),
            )
            # Don't fail the entire pipeline if summarization fails
            result.ai_summaries["error"] = f"Summarization failed: {str(e)}"

    async def _generate_ai_summaries_with_progress(
        self, result: QueryResult
    ) -> None:
        """Generate AI summaries with progress reporting."""
        if not result.metadata:
            await self._report_progress(
                result,
                "ai_summarization_skip",
                "Skipping AI summarization - no metadata available",
                85.0,
            )
            return

        try:
            # Generate batch summary for all results
            await self._report_progress(
                result,
                "batch_summary",
                "Generating overall summary of all results",
                80.0,
            )

            batch_summary = self.summarizer.summarize_batch_results(
                [{"metadata": metadata} for metadata in result.metadata],
                result.original_query,
            )
            result.ai_summaries["batch_summary"] = batch_summary

            await self._report_progress(
                result,
                "batch_summary_complete",
                "Overall summary generated successfully",
                82.0,
            )

            # Generate individual summaries for top results (limit to 5 for performance)
            top_results = result.metadata[:5]
            individual_summaries = []

            await self._report_progress(
                result,
                "individual_summaries",
                f"Generating detailed summaries for top {len(top_results)} datasets",
                83.0,
                {"count": len(top_results)},
            )

            for i, metadata in enumerate(top_results):
                progress = 83.0 + ((i / len(top_results)) * 5.0)

                try:
                    await self._report_progress(
                        result,
                        "summarizing_dataset",
                        f"Analyzing dataset {i+1}/{len(top_results)}: {metadata.get('accession', 'Unknown')}",
                        progress,
                        {
                            "current": i + 1,
                            "total": len(top_results),
                            "geo_id": metadata.get("accession", "Unknown"),
                        },
                    )

                    # Generate comprehensive summary for each dataset
                    summary = self.summarizer.summarize_dataset(
                        metadata,
                        query_context=result.original_query,
                        summary_type="comprehensive",
                    )
                    individual_summaries.append(
                        {
                            "accession": metadata.get("accession", "Unknown"),
                            "summary": summary,
                        }
                    )

                    await self._report_progress(
                        result,
                        "dataset_summary_complete",
                        f"Analysis complete for dataset {metadata.get('accession', 'Unknown')}",
                        progress,
                        {"geo_id": metadata.get("accession", "Unknown")},
                    )

                except Exception as e:
                    logger.warning(
                        "Failed to summarize dataset %s: %s",
                        metadata.get("accession", "Unknown"),
                        str(e),
                    )

                    await self._report_progress(
                        result,
                        "dataset_summary_error",
                        f"Error analyzing dataset {metadata.get('accession', 'Unknown')}: {str(e)}",
                        progress,
                        {
                            "geo_id": metadata.get("accession", "Unknown"),
                            "error": str(e),
                        },
                    )
                    continue

            result.ai_summaries["individual_summaries"] = individual_summaries

            # Generate a brief overall summary
            if len(result.metadata) > 0:
                await self._report_progress(
                    result,
                    "brief_overview",
                    "Creating quick overview of search results",
                    88.0,
                )

                first_result = result.metadata[0]
                brief_summary = self.summarizer.summarize_dataset(
                    first_result,
                    query_context=result.original_query,
                    summary_type="brief",
                )
                result.ai_summaries["brief_overview"] = brief_summary

                await self._report_progress(
                    result,
                    "brief_overview_complete",
                    "Quick overview generated successfully",
                    89.0,
                )

            logger.debug(
                "AI summaries generated successfully: %s", result.query_id
            )

        except Exception as e:
            logger.error(
                "Failed to generate AI summaries: %s - %s",
                result.query_id,
                str(e),
            )
            # Don't fail the entire pipeline if summarization fails
            result.ai_summaries["error"] = f"Summarization failed: {str(e)}"

            await self._report_progress(
                result,
                "ai_summarization_error",
                f"Error generating AI summaries: {str(e)}",
                89.0,
                {"error": str(e)},
            )
