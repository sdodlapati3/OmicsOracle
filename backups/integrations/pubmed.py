"""
Pubimport aiohttp
import ssl
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional, Any
import loggingntegration for OmicsOracle.

Provides functionality to search and retrieve research papers from PubMed
that are related to GEO datasets.
"""

import logging
import ssl
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

import aiohttp

logger = logging.getLogger(__name__)


class PubMedIntegration:
    """Integration with PubMed for retrieving related research papers."""

    BASE_URL = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils"

    def __init__(self, email: Optional[str] = None, api_key: Optional[str] = None):
        """
        Initialize PubMed integration.

        Args:
            email: Contact email for NCBI API (recommended)
            api_key: NCBI API key for higher rate limits
        """
        self.email = email
        self.api_key = api_key
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self) -> "PubMedIntegration":
        """Async context manager entry."""
        # Create SSL context that's more permissive for some environments
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        connector = aiohttp.TCPConnector(ssl=ssl_context)
        self.session = aiohttp.ClientSession(connector=connector)
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        if self.session:
            await self.session.close()

    def _build_params(self, **kwargs: str) -> Dict[str, str]:
        """Build common parameters for NCBI API calls."""
        params = {"tool": "OmicsOracle", "retmode": "xml"}

        if self.email:
            params["email"] = self.email

        if self.api_key:
            params["api_key"] = self.api_key

        params.update(kwargs)
        return params

    async def search_papers(
        self,
        geo_accession: str,
        title: Optional[str] = None,
        max_results: int = 20,
    ) -> List[str]:
        """
        Search for papers related to a GEO dataset.

        Args:
            geo_accession: GEO accession number (e.g., GSE12345)
            title: Optional dataset title for better search
            max_results: Maximum number of results to return

        Returns:
            List of PubMed IDs
        """
        if not self.session:
            raise RuntimeError("Session not initialized. Use async context manager.")

        # Build search query
        search_terms = [geo_accession]
        if title:
            # Extract key terms from title
            title_words = [word for word in title.split() if len(word) > 3]
            search_terms.extend(title_words[:5])  # Limit to avoid overly complex queries

        query = " OR ".join(f'"{term}"' for term in search_terms)

        # Search parameters
        params = self._build_params(db="pubmed", term=query, retmax=str(max_results), sort="relevance")

        url = f"{self.BASE_URL}/esearch.fcgi"

        try:
            async with self.session.get(url, params=params) as response:
                response.raise_for_status()
                xml_content = await response.text()

            # Parse XML response
            root = ET.fromstring(xml_content)
            id_list = root.find(".//IdList")

            if id_list is not None:
                pmids = [id_elem.text for id_elem in id_list.findall("Id") if id_elem.text]
                logger.info(f"Found {len(pmids)} papers for {geo_accession}")
                return pmids
            else:
                logger.warning(f"No papers found for {geo_accession}")
                return []

        except Exception as e:
            logger.error(f"Error searching PubMed for {geo_accession}: {e}")
            return []

    async def fetch_paper_details(self, pmids: List[str]) -> List[Dict[str, Any]]:
        """
        Fetch detailed information for given PubMed IDs.

        Args:
            pmids: List of PubMed IDs

        Returns:
            List of paper details dictionaries
        """
        if not self.session or not pmids:
            return []

        # Convert list to comma-separated string
        id_list = ",".join(pmids)

        params = self._build_params(db="pubmed", id=id_list, rettype="abstract")

        url = f"{self.BASE_URL}/efetch.fcgi"

        try:
            async with self.session.get(url, params=params) as response:
                response.raise_for_status()
                xml_content = await response.text()

            # Parse XML response
            root = ET.fromstring(xml_content)
            papers = []

            for article in root.findall(".//PubmedArticle"):
                paper_info = self._extract_paper_info(article)
                if paper_info:
                    papers.append(paper_info)

            logger.info(f"Fetched details for {len(papers)} papers")
            return papers

        except Exception as e:
            logger.error(f"Error fetching paper details: {e}")
            return []

    def _extract_paper_info(self, article_elem: ET.Element) -> Optional[Dict[str, Any]]:
        """Extract paper information from XML element."""
        try:
            medline_citation = article_elem.find(".//MedlineCitation")
            if medline_citation is None:
                return None

            pmid_elem = medline_citation.find(".//PMID")
            pmid = pmid_elem.text if pmid_elem is not None else None

            article = medline_citation.find(".//Article")
            if article is None:
                return None

            # Extract title
            title_elem = article.find(".//ArticleTitle")
            title = title_elem.text if title_elem is not None else "No title"

            # Extract authors
            authors = []
            author_list = article.find(".//AuthorList")
            if author_list is not None:
                for author in author_list.findall(".//Author"):
                    last_name = author.find(".//LastName")
                    first_name = author.find(".//ForeName")
                    if last_name is not None and last_name.text:
                        author_name = last_name.text
                        if first_name is not None and first_name.text:
                            author_name += f", {first_name.text}"
                        authors.append(author_name)

            # Extract journal and publication info
            journal_elem = article.find(".//Journal/Title")
            journal = journal_elem.text if journal_elem is not None else "Unknown journal"

            pub_date = article.find(".//PubDate")
            year = None
            if pub_date is not None:
                year_elem = pub_date.find(".//Year")
                year = year_elem.text if year_elem is not None else None

            # Extract abstract
            abstract_elem = article.find(".//Abstract/AbstractText")
            abstract = abstract_elem.text if abstract_elem is not None else None

            return {
                "pmid": pmid,
                "title": title,
                "authors": authors,
                "journal": journal,
                "year": year,
                "abstract": abstract,
                "pubmed_url": f"https://pubmed.ncbi.nlm.nih.gov/{pmid}/" if pmid else None,
            }

        except Exception as e:
            logger.error(f"Error extracting paper info: {e}")
            return None

    async def get_related_papers(
        self,
        geo_accession: str,
        title: Optional[str] = None,
        max_results: int = 10,
    ) -> List[Dict[str, Any]]:
        """
        Get related papers for a GEO dataset with full details.

        Args:
            geo_accession: GEO accession number
            title: Optional dataset title
            max_results: Maximum number of results

        Returns:
            List of paper details with abstracts
        """
        # Search for paper IDs
        pmids = await self.search_papers(geo_accession, title, max_results)

        if not pmids:
            return []

        # Fetch detailed information
        papers = await self.fetch_paper_details(pmids)

        return papers


# Convenience function for one-off searches
async def search_pubmed_for_geo(
    geo_accession: str,
    title: Optional[str] = None,
    max_results: int = 10,
    email: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Convenience function to search PubMed for papers related to a GEO dataset.

    Args:
        geo_accession: GEO accession number
        title: Optional dataset title
        max_results: Maximum number of results
        email: Contact email for NCBI API

    Returns:
        List of paper details
    """
    async with PubMedIntegration(email=email) as pubmed:
        return await pubmed.get_related_papers(geo_accession, title, max_results)
