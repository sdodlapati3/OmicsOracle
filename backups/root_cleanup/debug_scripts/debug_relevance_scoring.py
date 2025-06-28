#!/usr/bin/env python3
"""
Debug relevance scoring by examining the actual calculation process.
"""

import asyncio
import os
import sys

# Add the src directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from omics_oracle.application.dto.search_dto import SearchRequestDTO
from omics_oracle.application.use_cases.enhanced_search_datasets import EnhancedSearchDatasetsUseCase
from omics_oracle.infrastructure.config.settings import get_settings
from omics_oracle.infrastructure.external_apis.geo_client import GEOClient
from omics_oracle.infrastructure.repositories.geo_search_repository import GEOSearchRepository


async def debug_relevance_scoring():
    """Debug the relevance scoring process."""

    # Initialize components
    settings = get_settings()
    geo_client = GEOClient(settings.entrez_email)
    search_repository = GEOSearchRepository(geo_client)
    search_use_case = EnhancedSearchDatasetsUseCase(search_repository)

    # Test query
    test_query = "cancer gene expression"

    print(f"Testing relevance scoring for query: '{test_query}'")
    print("=" * 60)

    # Create search request
    search_request = SearchRequestDTO(query=test_query, max_results=5)

    try:
        # Execute search
        search_response = await search_use_case.execute(search_request)

        print(f"Found {len(search_response.datasets)} results:")
        print()

        for i, dataset in enumerate(search_response.datasets):
            print(f"Result {i+1}:")
            print(f"  ID: {dataset.geo_id}")
            print(f"  Title: {dataset.title[:100]}...")
            print(f"  Relevance Score: {dataset.relevance_score}")
            print(f"  Organism: {dataset.organism}")

            # Manual calculation debug
            print(f"  Manual scoring debug:")
            score = search_use_case._calculate_relevance_score(test_query, dataset)
            print(f"    Calculated score: {score}")

            # Check what text fields contain
            query_terms = test_query.lower().split()
            title_matches = sum(1 for term in query_terms if term in (dataset.title or "").lower())
            summary_matches = sum(1 for term in query_terms if term in (dataset.summary or "").lower())
            desc_matches = sum(1 for term in query_terms if term in (dataset.description or "").lower())

            print(f"    Query terms: {query_terms}")
            print(f"    Title matches: {title_matches}/{len(query_terms)}")
            print(f"    Summary matches: {summary_matches}/{len(query_terms)}")
            print(f"    Description matches: {desc_matches}/{len(query_terms)}")
            print()

    except Exception as e:
        print(f"Error during search: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(debug_relevance_scoring())
