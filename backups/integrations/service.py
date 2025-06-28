"""
Integration service that combines PubMed and citation management features.
"""

import logging
from typing import Any, Dict, List, Optional

from .citation_managers import CitationManagerIntegration
from .pubmed import PubMedIntegration

logger = logging.getLogger(__name__)


class IntegrationService:
    """Service that combines multiple third-party integrations."""

    def __init__(
        self,
        pubmed_email: Optional[str] = None,
        pubmed_api_key: Optional[str] = None,
    ):
        """
        Initialize integration service.

        Args:
            pubmed_email: Email for PubMed API
            pubmed_api_key: API key for PubMed (optional)
        """
        self.pubmed_email = pubmed_email
        self.pubmed_api_key = pubmed_api_key
        self.citation_manager = CitationManagerIntegration()

    async def enrich_geo_dataset(
        self,
        geo_data: Dict[str, Any],
        include_papers: bool = True,
        max_papers: int = 10,
    ) -> Dict[str, Any]:
        """
        Enrich GEO dataset with related papers and citation information.

        Args:
            geo_data: GEO dataset information
            include_papers: Whether to fetch related papers
            max_papers: Maximum number of papers to fetch

        Returns:
            Enriched dataset with papers and citation info
        """
        enriched_data = geo_data.copy()

        if include_papers:
            try:
                async with PubMedIntegration(email=self.pubmed_email, api_key=self.pubmed_api_key) as pubmed:
                    papers = await pubmed.get_related_papers(
                        geo_data.get("accession", ""),
                        geo_data.get("title"),
                        max_papers,
                    )
                    enriched_data["related_papers"] = papers
                    logger.info(f"Found {len(papers)} related papers for {geo_data.get('accession')}")

            except Exception as e:
                logger.error(f"Failed to fetch related papers: {e}")
                enriched_data["related_papers"] = []

        # Add citation information
        reference = self.citation_manager.format_geo_reference(
            enriched_data, enriched_data.get("related_papers")
        )
        enriched_data["citation_info"] = reference

        return enriched_data

    async def batch_enrich_datasets(
        self,
        geo_datasets: List[Dict[str, Any]],
        include_papers: bool = True,
        max_papers: int = 5,
    ) -> List[Dict[str, Any]]:
        """
        Enrich multiple GEO datasets in batch.

        Args:
            geo_datasets: List of GEO dataset information
            include_papers: Whether to fetch related papers
            max_papers: Maximum papers per dataset

        Returns:
            List of enriched datasets
        """
        enriched_datasets = []

        for dataset in geo_datasets:
            try:
                enriched = await self.enrich_geo_dataset(dataset, include_papers, max_papers)
                enriched_datasets.append(enriched)

            except Exception as e:
                logger.error(f"Failed to enrich dataset {dataset.get('accession', 'unknown')}: {e}")
                # Add the original dataset with empty enrichment
                dataset["related_papers"] = []
                dataset["citation_info"] = self.citation_manager.format_geo_reference(dataset)
                enriched_datasets.append(dataset)

        return enriched_datasets

    def export_citations(
        self,
        geo_datasets: List[Dict[str, Any]],
        format_type: str = "bibtex",
        include_papers: bool = True,
    ) -> str:
        """
        Export citations for multiple datasets.

        Args:
            geo_datasets: List of enriched GEO datasets
            format_type: Citation format ('bibtex', 'ris', 'endnote', 'csl-json')
            include_papers: Whether to include related paper info

        Returns:
            Formatted citations string
        """
        return self.citation_manager.export_references(geo_datasets, format_type, include_papers)

    async def create_research_bibliography(
        self,
        geo_datasets: List[Dict[str, Any]],
        format_type: str = "bibtex",
        max_papers_per_dataset: int = 3,
    ) -> str:
        """
        Create a comprehensive research bibliography for GEO datasets.

        Args:
            geo_datasets: List of GEO dataset information
            format_type: Citation format
            max_papers_per_dataset: Max papers to include per dataset

        Returns:
            Complete bibliography string
        """
        # First enrich all datasets with papers
        enriched_datasets = await self.batch_enrich_datasets(
            geo_datasets, include_papers=True, max_papers=max_papers_per_dataset
        )

        # Export as citations
        return self.export_citations(enriched_datasets, format_type, True)
