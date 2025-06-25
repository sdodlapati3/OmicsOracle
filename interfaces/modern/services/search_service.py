"""
Search service for OmicsOracle modern interface
Handles search operations and result processing
"""

import re
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from core.exceptions import SearchException, ValidationException
from core.logging_config import get_search_logger
from models import SearchQuery, SearchResponse, SearchResult, SearchType


class SearchService:
    """Service for handling search operations"""

    def __init__(self):
        self.logger = get_search_logger()
        self.organism_patterns = {
            r"\b(homo sapiens|human|hsa)\b": "Homo sapiens",
            r"\b(mus musculus|mouse|mmu)\b": "Mus musculus",
            r"\b(rattus norvegicus|rat|rno)\b": "Rattus norvegicus",
            r"\b(arabidopsis thaliana|arabidopsis|ath)\b": "Arabidopsis thaliana",
            r"\b(drosophila melanogaster|drosophila|dme)\b": "Drosophila melanogaster",
            r"\b(saccharomyces cerevisiae|yeast|sce)\b": "Saccharomyces cerevisiae",
            r"\b(caenorhabditis elegans|c\.?\s*elegans|cel)\b": "Caenorhabditis elegans",
            r"\b(escherichia coli|e\.?\s*coli|eco)\b": "Escherichia coli",
        }
        self.human_indicators = [
            "patient",
            "clinical",
            "hospital",
            "covid-19",
            "disease",
            "blood",
            "plasma",
            "serum",
            "biopsy",
            "tumor",
            "cancer",
        ]

    async def search(self, query: SearchQuery) -> SearchResponse:
        """
        Perform search operation based on query parameters

        Args:
            query: Search query parameters

        Returns:
            SearchResponse with results and metadata

        Raises:
            SearchException: If search operation fails
            ValidationException: If query parameters are invalid
        """
        start_time = time.time()

        try:
            self.logger.info(
                f"Processing search: '{query.query}' (page: {query.page}, size: {query.page_size})"
            )

            # Validate query
            self._validate_query(query)

            # Get pipeline (this will need to be injected or imported from existing code)
            pipeline = self._get_pipeline()

            if not pipeline:
                raise SearchException("Search pipeline not available")

            # Calculate pagination
            offset = (query.page - 1) * query.page_size

            # Execute search with the OmicsOracle pipeline
            if hasattr(pipeline, "search_datasets"):
                # Use the web-optimized search method
                pipeline_results = await pipeline.search_datasets(
                    query.query, max_results=min(query.page_size * 2, 100)
                )
            else:
                # Fall back to process_query method
                pipeline_results = await pipeline.process_query(
                    query.query, max_results=min(query.page_size * 2, 100)
                )

            if not pipeline_results or not hasattr(
                pipeline_results, "metadata"
            ):
                return SearchResponse(
                    results=[],
                    total_count=0,
                    page=query.page,
                    page_size=query.page_size,
                    total_pages=0,
                    query=query.query,
                    search_type=query.search_type,
                    execution_time=time.time() - start_time,
                )

            # Process results
            all_results = pipeline_results.metadata
            total_available = len(all_results)

            # Apply pagination
            start_idx = offset
            end_idx = min(offset + query.page_size, total_available)
            results_subset = all_results[start_idx:end_idx]

            # Convert to SearchResult objects
            search_results = []
            ai_summaries = getattr(pipeline_results, "ai_summaries", {})

            for idx, result_data in enumerate(results_subset):
                search_result = self._process_result(result_data, ai_summaries)
                search_results.append(search_result)

            # Calculate pagination metadata
            total_pages = (
                total_available + query.page_size - 1
            ) // query.page_size
            execution_time = time.time() - start_time

            self.logger.info(
                f"Search completed: {len(search_results)} results in {execution_time:.3f}s"
            )

            return SearchResponse(
                results=search_results,
                total_count=total_available,
                page=query.page,
                page_size=query.page_size,
                total_pages=total_pages,
                query=query.query,
                search_type=query.search_type,
                execution_time=execution_time,
                filters_applied=query.filters,
            )

        except Exception as e:
            self.logger.error(
                f"Search failed for query '{query.query}': {str(e)}",
                exc_info=True,
            )
            if isinstance(e, (SearchException, ValidationException)):
                raise
            raise SearchException(f"Search operation failed: {str(e)}")

    def _validate_query(self, query: SearchQuery) -> None:
        """Validate search query parameters"""
        if not query.query or not query.query.strip():
            raise ValidationException("Search query cannot be empty")

        if len(query.query) > 1000:
            raise ValidationException(
                "Search query is too long (max 1000 characters)"
            )

        if query.page < 1:
            raise ValidationException("Page number must be positive")

        if query.page_size < 1 or query.page_size > 100:
            raise ValidationException("Page size must be between 1 and 100")

    def _get_pipeline(self):
        """Get the OmicsOracle pipeline"""
        try:
            # Import the actual OmicsOracle pipeline
            import os
            import sys

            # Add the src directory to path
            project_root = os.path.dirname(
                os.path.dirname(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                )
            )
            src_path = os.path.join(project_root, "src")
            if src_path not in sys.path:
                sys.path.insert(0, src_path)

            from omics_oracle.core.config import Config
            from omics_oracle.pipeline.pipeline import OmicsOracle

            # Initialize with configuration
            config = Config()
            pipeline = OmicsOracle(config)

            self.logger.info("OmicsOracle pipeline initialized successfully")
            return pipeline

        except ImportError as e:
            self.logger.warning(f"OmicsOracle pipeline not available: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Failed to initialize OmicsOracle pipeline: {e}")
            return None

    def _process_result(
        self, result_data: Any, ai_summaries: Dict[str, Any]
    ) -> SearchResult:
        """Process a single search result"""
        try:
            # Extract basic information
            geo_id = (
                self._extract_field(result_data, ["geo_id", "id", "accession"])
                or "unknown"
            )
            title = (
                self._extract_field(result_data, ["title", "name"])
                or "Untitled"
            )
            abstract = self._extract_field(
                result_data, ["summary", "abstract", "description"]
            )

            # Extract organism
            organism = self._extract_organism(result_data)

            # Extract sample count
            sample_count = self._extract_sample_count(result_data)

            # Extract authors (if available)
            authors = (
                self._extract_field(result_data, ["authors", "contributor"])
                or []
            )
            if isinstance(authors, str):
                authors = [authors]

            # Extract publication info
            journal = self._extract_field(result_data, ["journal", "source"])
            doi = self._extract_field(result_data, ["doi"])
            pmid = self._extract_field(result_data, ["pmid", "pubmed_id"])
            url = self._extract_field(result_data, ["url", "link"])

            # Get AI summary
            ai_summary = self._extract_ai_summary(result_data, ai_summaries)

            # Create metadata
            metadata = {
                "organism": organism,
                "sample_count": sample_count,
                "ai_summary": ai_summary,
            }

            # Add any additional metadata
            for field in ["platform", "study_type", "overall_design"]:
                value = self._extract_field(result_data, [field])
                if value:
                    metadata[field] = value

            return SearchResult(
                id=geo_id,
                title=title,
                abstract=abstract,
                authors=authors,
                journal=journal,
                doi=doi,
                pmid=pmid,
                url=url,
                relevance_score=0.0,  # TODO: Calculate relevance score
                metadata=metadata,
            )

        except Exception as e:
            self.logger.warning(f"Failed to process result: {str(e)}")
            return SearchResult(
                id="unknown",
                title="Processing Error",
                abstract=f"Error processing result: {str(e)}",
                metadata={"error": str(e)},
            )

    def _extract_field(
        self, data: Any, field_names: List[str]
    ) -> Optional[str]:
        """Extract field value from data using multiple possible field names"""
        for field_name in field_names:
            try:
                # Try dictionary access
                if hasattr(data, "get"):
                    value = data.get(field_name)
                    if value and str(value).strip():
                        return str(value).strip()

                # Try attribute access
                value = getattr(data, field_name, None)
                if value and str(value).strip():
                    return str(value).strip()

            except Exception:
                continue

        return None

    def _extract_organism(self, data: Any) -> str:
        """Extract organism information from result data"""
        # Try direct field extraction first
        organism = self._extract_field(data, ["organism", "species", "taxon"])

        if organism and organism != "Unknown":
            return organism

        # Try pattern matching on text content
        text_content = self._get_text_content(data)
        if text_content:
            text_lower = text_content.lower()

            # Check organism patterns
            for pattern, organism_name in self.organism_patterns.items():
                if re.search(pattern, text_lower):
                    self.logger.debug(
                        f"Extracted organism from text: {organism_name}"
                    )
                    return organism_name

            # Check for human indicators
            if any(
                indicator in text_lower for indicator in self.human_indicators
            ):
                self.logger.debug("Inferred human based on clinical context")
                return "Homo sapiens"

        return "Unknown"

    def _extract_sample_count(self, data: Any) -> str:
        """Extract sample count from result data"""
        sample_count = self._extract_field(
            data, ["sample_count", "n_samples", "samples"]
        )

        if not sample_count:
            return "Unknown"

        # Handle list representations
        if isinstance(sample_count, list):
            return str(len(sample_count))

        if isinstance(sample_count, str) and sample_count.startswith("["):
            try:
                sample_list = eval(sample_count)
                if isinstance(sample_list, list):
                    return str(len(sample_list))
            except Exception:
                pass

        return str(sample_count)

    def _get_text_content(self, data: Any) -> str:
        """Get all text content from result data for pattern matching"""
        text_parts = []

        for field in [
            "summary",
            "title",
            "overall_design",
            "description",
            "abstract",
        ]:
            value = self._extract_field(data, [field])
            if value:
                text_parts.append(value)

        return " ".join(text_parts)

    def _extract_ai_summary(
        self, result_data: Any, ai_summaries: Dict[str, Any]
    ) -> str:
        """Extract AI summary for the result"""
        if not ai_summaries:
            return ""

        # Try to find individual summary
        individual_summaries = ai_summaries.get("individual_summaries", [])
        if individual_summaries:
            result_str = str(result_data)

            for summary_item in individual_summaries:
                if not isinstance(summary_item, dict):
                    continue

                # Check if any key matches content in result
                for key in summary_item.keys():
                    if key != "summary" and key in result_str:
                        return summary_item.get("summary", "")

        # Fall back to brief overview
        return ai_summaries.get("brief_overview", "")
