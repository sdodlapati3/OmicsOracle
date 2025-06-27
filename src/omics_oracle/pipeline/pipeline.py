"""
Core Pipeline Implementation for OmicsOracle

This module provides the main OmicsOracle class that orchestrates the entire
pipeline from natural language query to biological data retrieval and analysis.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from ..core.config import Config
from ..core.exceptions import OmicsOracleException
from ..geo_tools.geo_client import UnifiedGEOClient
from ..nlp.biomedical_ner import BiomedicalNER, EnhancedBiologicalSynonymMapper
from ..nlp.prompt_interpreter import PromptInterpreter
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


class OmicsOracle:
    """
    Main pipeline class that orchestrates biological data search and analysis.

    This class integrates natural language processing, GEO database search,
    and data processing to provide a comprehensive biological data analysis
    pipeline.
    """

    def __init__(self, config: Optional[Config] = None):
        """
        Initialize OmicsOracle pipeline.

        Args:
            config: Configuration object. If None, loads from default sources.
        """
        self.config = config or Config()
        self._setup_logging()

        # Initialize components
        self.geo_client = UnifiedGEOClient(self.config)
        self.nlp_interpreter = PromptInterpreter()
        self.biomedical_ner = BiomedicalNER()
        self.synonym_mapper = EnhancedBiologicalSynonymMapper()
        self.summarizer = SummarizationService(self.config)

        # Pipeline state
        self._active_queries: Dict[str, QueryResult] = {}
        self._query_counter = 0

        logger.info("OmicsOracle pipeline initialized successfully")

    def _setup_logging(self) -> None:
        """Set up logging configuration."""
        logging.basicConfig(
            level=getattr(logging, self.config.logging.level.upper()),
            format=self.config.logging.format,
        )

    def _generate_query_id(self) -> str:
        """Generate a unique query ID."""
        self._query_counter += 1
        return f"query_{self._query_counter:06d}"

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

        try:
            # Step 1: Parse natural language query
            result.status = QueryStatus.PARSING
            await self._parse_query(result)

            # Step 2: Search for relevant GEO data
            result.status = QueryStatus.SEARCHING
            await self._search_geo_data(result, max_results)

            # Step 3: Process and enhance results
            result.status = QueryStatus.PROCESSING
            await self._process_results(result, include_sra)

            # Step 4: Format results
            await self._format_results(result, result_format)

            result.status = QueryStatus.COMPLETED
            result.end_time = datetime.now()

            logger.info(
                "Query processing completed: %s (duration: %.2fs)",
                query_id,
                result.duration,
            )

        except Exception as e:
            result.status = QueryStatus.FAILED
            result.error = str(e)
            result.end_time = datetime.now()
            logger.error("Query processing failed: %s - %s", query_id, str(e))
            raise OmicsOracleException(
                f"Pipeline processing failed: {str(e)}"
            ) from e

        return result

    async def _parse_query(self, result: QueryResult) -> None:
        """Parse natural language query and extract entities."""
        logger.debug("Parsing query: %s", result.query_id)

        # Extract intent using prompt interpreter
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

        # Extract biomedical entities
        entities = self.biomedical_ner.extract_biomedical_entities(
            result.original_query
        )
        result.entities = entities

        result.add_step("entity_extraction", {"entities": entities})

        # Expand query with synonyms
        expanded_terms = set()
        for entity_type, entity_list in entities.items():
            for entity in entity_list:
                entity_text = entity["text"].lower()
                synonyms = self.synonym_mapper.get_synonyms(
                    entity_text, entity_type
                )
                expanded_terms.update(synonyms)

        if expanded_terms:
            result.expanded_query = " ".join(
                [result.original_query] + list(expanded_terms)[:10]
            )
        else:
            result.expanded_query = result.original_query

        result.add_step(
            "query_expansion",
            {
                "original": result.original_query,
                "expanded": result.expanded_query,
                "added_terms": list(expanded_terms)[:10],
            },
        )

        logger.debug("Query parsing completed for: %s", result.query_id)

    async def _search_geo_data(
        self, result: QueryResult, max_results: int
    ) -> None:
        """Search GEO database for relevant data."""
        logger.debug("Searching GEO data: %s", result.query_id)

        # Use expanded query for better search results
        search_query = result.expanded_query or result.original_query

        try:
            # Search for GEO series IDs
            geo_ids = await self.geo_client.search_geo_series(
                search_query, max_results=max_results
            )
            result.geo_ids = geo_ids

            result.add_step(
                "geo_search",
                {
                    "search_query": search_query,
                    "geo_ids": geo_ids,
                    "count": len(geo_ids),
                },
            )

            logger.debug(
                "GEO search completed: %s (found %d results)",
                result.query_id,
                len(geo_ids),
            )

        except Exception as e:
            logger.error("GEO search failed: %s - %s", result.query_id, str(e))
            result.add_step("geo_search_error", {"error": str(e)})
            # Continue with empty results rather than failing completely
            result.geo_ids = []

    async def _process_results(
        self, result: QueryResult, include_sra: bool
    ) -> None:
        """Process and enhance search results."""
        logger.debug("Processing results: %s", result.query_id)

        metadata_list = []

        # Process each GEO ID
        for geo_id in result.geo_ids[:20]:  # Limit to prevent overwhelming
            try:
                metadata = await self.geo_client.get_geo_metadata(
                    geo_id, include_sra=include_sra
                )
                if metadata:
                    # Enhance metadata with relevance scoring
                    enhanced_metadata = await self._enhance_metadata(
                        metadata, result
                    )
                    metadata_list.append(enhanced_metadata)

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

    async def search_datasets(
        self,
        query: str,
        max_results: int = 100,
        include_sra: bool = False,
        organism: Optional[str] = None,
        assay_type: Optional[str] = None,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None,
    ) -> QueryResult:
        """
        Search for datasets with optional filters.

        This is a wrapper around process_query that adds filtering capabilities.

        Args:
            query: Natural language query
            max_results: Maximum number of results to return
            include_sra: Whether to include SRA metadata
            organism: Organism filter (e.g., 'homo sapiens')
            assay_type: Assay type filter (e.g., 'RNA-seq')
            date_from: Start date filter (YYYY-MM-DD)
            date_to: End date filter (YYYY-MM-DD)

        Returns:
            QueryResult object with processing results
        """
        # For now, we'll process the query and then filter results
        # In a more advanced implementation, these filters could be
        # passed to the GEO search to reduce the initial result set

        result = await self.process_query(
            query=query,
            max_results=max_results
            * 2,  # Get more results to allow for filtering
            include_sra=include_sra,
        )

        # Apply filters to the results
        if any([organism, assay_type, date_from, date_to]):
            filtered_metadata = []

            for dataset in result.metadata:
                # Apply organism filter
                if organism and organism.lower() not in (
                    dataset.get("organism", "").lower()
                ):
                    continue

                # Apply assay type filter (check in title, summary, or platform)
                if assay_type:
                    assay_text = f"{dataset.get('title', '')} {dataset.get('summary', '')} {dataset.get('platform', '')}".lower()
                    if assay_type.lower() not in assay_text:
                        continue

                # Apply date filters
                pub_date = dataset.get("publication_date", "")
                if date_from and pub_date and pub_date < date_from:
                    continue
                if date_to and pub_date and pub_date > date_to:
                    continue

                filtered_metadata.append(dataset)

                # Stop when we have enough results
                if len(filtered_metadata) >= max_results:
                    break

            result.metadata = filtered_metadata

            # Update result summary
            result.add_step(
                "filtering",
                {
                    "applied_filters": {
                        "organism": organism,
                        "assay_type": assay_type,
                        "date_from": date_from,
                        "date_to": date_to,
                    },
                    "filtered_count": len(filtered_metadata),
                },
            )

            logger.info(
                "Applied filters to query %s: %d -> %d results",
                result.query_id,
                len(result.metadata)
                if not any([organism, assay_type, date_from, date_to])
                else "unknown",
                len(filtered_metadata),
            )

        return result
