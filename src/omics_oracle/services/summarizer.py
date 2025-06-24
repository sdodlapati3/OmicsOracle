"""
LLM-powered summarization service for OmicsOracle.

This service provides:
- Natural language dataset summaries
- Intelligent experiment descriptions
- Contextual analysis of GEO metadata
- Research insights and recommendations
"""

import logging
import os
from typing import Any, Dict, List, Optional

from openai import OpenAI

from ..core.config import Config
from .cache import SummaryCache

try:
    from .cost_manager import cost_manager

    COST_TRACKING_AVAILABLE = True
except ImportError:
    COST_TRACKING_AVAILABLE = False

logger = logging.getLogger(__name__)


class SummarizationService:
    """Service for generating AI-powered summaries of genomics datasets."""

    def __init__(self, config: Optional[Config] = None) -> None:
        """Initialize summarization service with OpenAI client."""
        self.config = config or Config()

        # Initialize caching
        self.cache = SummaryCache()

        # Initialize OpenAI client
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            logger.warning(
                "OpenAI API key not found. Summarization will use fallback mode."
            )
            self.client = None
        else:
            self.client = OpenAI(api_key=api_key)

        # Model configuration
        self.model = "gpt-4o-mini"  # Cost-effective model for summarization
        self.max_tokens = 500
        self.temperature = 0.3  # Low temperature for consistent, factual output

        logger.info("Summarization service initialized")

    def summarize_dataset(
        self,
        metadata: Dict[str, Any],
        query_context: Optional[str] = None,
        summary_type: str = "comprehensive",
    ) -> Dict[str, str]:
        """
        Generate AI-powered summary of a GEO dataset.

        Args:
            metadata: Dataset metadata from GEO
            query_context: Original user query for context
            summary_type: Type of summary ('brief', 'comprehensive', 'technical')

        Returns:
            Dictionary with summary components
        """
        if not self.client:
            return self._generate_fallback_summary(metadata)

        # Create cache key based on dataset and query context
        dataset_id = metadata.get("accession", metadata.get("id", "unknown"))
        cache_key = (
            f"{dataset_id}_{query_context or 'no_context'}_{summary_type}"
        )

        # Check cache first
        cached_summary = self.cache.get(cache_key, "dataset_summary")
        if cached_summary:
            logger.info(f"Using cached summary for dataset: {dataset_id}")
            return cached_summary

        try:
            # Prepare metadata for summarization
            cleaned_metadata = self._prepare_metadata(metadata)

            # Generate different summary components
            summaries = {}

            if summary_type in ["brief", "comprehensive"]:
                summaries["overview"] = self._generate_overview(
                    cleaned_metadata, query_context
                )

            if summary_type in ["comprehensive", "technical"]:
                summaries["methodology"] = self._generate_methodology_summary(
                    cleaned_metadata
                )
                summaries["significance"] = self._generate_significance_summary(
                    cleaned_metadata, query_context
                )

            if summary_type == "brief":
                summaries["brief"] = self._generate_brief_summary(
                    cleaned_metadata, query_context
                )

            # Add technical details for comprehensive summaries
            if summary_type == "comprehensive":
                summaries[
                    "technical_details"
                ] = self._generate_technical_summary(cleaned_metadata)

            # Cache the summary (estimate tokens used)
            estimated_tokens = sum(
                len(str(v).split()) * 1.3 for v in summaries.values()
            )
            self.cache.set(
                cache_key,
                "dataset_summary",
                summaries,
                token_count=int(estimated_tokens),
            )

            return summaries

        except Exception as e:
            logger.error(f"Error generating AI summary: {e}")
            return self._generate_fallback_summary(metadata)

    def _prepare_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Clean and prepare metadata for LLM processing."""
        # Handle case where metadata might be a string or have unexpected structure
        if isinstance(metadata, str):
            return {
                "accession": "Unknown",
                "title": metadata[:200]
                if len(metadata) > 200
                else str(metadata),
                "summary": str(metadata),
                "type": "Unknown",
                "organism": "Unknown",
                "platform": "Unknown",
                "sample_count": 0,
                "submission_date": "",
                "last_update_date": "",
            }

        # Extract key fields and clean them
        cleaned = {
            "accession": metadata.get(
                "accession", metadata.get("geo_id", "Unknown")
            ),
            "title": metadata.get("title", metadata.get("name", "")),
            "summary": metadata.get("summary", metadata.get("description", "")),
            "type": metadata.get("type", metadata.get("study_type", "")),
            "organism": metadata.get("organism", metadata.get("species", "")),
            "platform": metadata.get(
                "platform", metadata.get("technology", "")
            ),
            "sample_count": len(metadata.get("samples", [])),
            "submission_date": metadata.get(
                "submission_date", metadata.get("date", "")
            ),
            "last_update_date": metadata.get("last_update_date", ""),
        }

        # Add sample information if available
        samples = metadata.get("samples", [])
        if samples and isinstance(samples, list):
            sample_titles = []
            for s in samples[:5]:
                if isinstance(s, dict):
                    sample_titles.append(s.get("title", s.get("name", "")))
                elif isinstance(s, str):
                    sample_titles.append(s)
            cleaned["sample_examples"] = sample_titles

        return cleaned

    def _generate_overview(
        self, metadata: Dict[str, Any], query_context: Optional[str]
    ) -> str:
        """Generate high-level overview summary."""
        prompt = self._build_overview_prompt(metadata, query_context)

        try:
            if not self.client:
                return f"Dataset {metadata.get('accession', 'Unknown')}: {metadata.get('title', 'No title available')}"

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a genomics research expert who creates clear, "
                            "accessible summaries of scientific datasets. Focus on the "
                            "biological significance and research context."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                max_tokens=self.max_tokens,
                temperature=self.temperature,
            )

            content = response.choices[0].message.content
            return (
                content.strip()
                if content
                else f"Dataset {metadata.get('accession', 'Unknown')}: {metadata.get('title', 'No title available')}"
            )

        except Exception as e:
            logger.error(f"Error generating overview: {e}")
            return f"Dataset {metadata.get('accession', 'Unknown')}: {metadata.get('title', 'No title available')}"

    def _generate_methodology_summary(self, metadata: Dict[str, Any]) -> str:
        """Generate methodology and experimental design summary."""
        prompt = f"""
        Analyze this genomics dataset and provide a concise summary of the experimental methodology:

        Dataset: {metadata.get('accession', 'Unknown')}
        Title: {metadata.get('title', 'No title')}
        Type: {metadata.get('type', 'Unknown')}
        Platform: {metadata.get('platform', 'Unknown')}
        Organism: {metadata.get('organism', 'Unknown')}
        Samples: {metadata.get('sample_count', 0)}

        Description: {metadata.get('summary', 'No description available')[:1000]}

        Focus on:
        1. Experimental technique/assay type
        2. Sample characteristics and experimental design
        3. Technical platform and methodology
        4. Key experimental parameters

        Provide a technical but accessible summary in 2-3 sentences.
        """

        try:
            if not self.client:
                return f"Experimental methodology using {metadata.get('platform', 'unknown platform')} technology."

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a genomics methods expert. Provide clear, "
                            "technical summaries of experimental methodologies."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                max_tokens=300,
                temperature=self.temperature,
            )

            content = response.choices[0].message.content
            return (
                content.strip()
                if content
                else f"Experimental methodology using {metadata.get('platform', 'unknown platform')} technology."
            )

        except Exception as e:
            logger.error(f"Error generating methodology summary: {e}")
            return f"Experimental methodology using {metadata.get('platform', 'unknown platform')} technology."

    def _generate_significance_summary(
        self, metadata: Dict[str, Any], query_context: Optional[str]
    ) -> str:
        """Generate research significance and implications summary."""
        prompt = f"""
        Analyze the research significance of this genomics dataset:

        Dataset: {metadata.get('accession', 'Unknown')} - {metadata.get('title', 'No title')}
        Context: {query_context or 'General genomics research'}
        Organism: {metadata.get('organism', 'Unknown')}
        Study Type: {metadata.get('type', 'Unknown')}

        Description: {metadata.get('summary', 'No description available')[:1000]}

        Explain:
        1. Scientific significance and research impact
        2. Relevance to the field of genomics/epigenomics
        3. Potential applications or follow-up research
        4. Connection to the user's query context

        Provide insights in 2-3 sentences focusing on biological significance.
        """

        try:
            if not self.client:
                return "This dataset contributes to our understanding of genomic mechanisms and biological processes."

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a genomics research analyst who identifies "
                            "the broader scientific significance of research datasets."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                max_tokens=300,
                temperature=self.temperature,
            )

            content = response.choices[0].message.content
            return (
                content.strip()
                if content
                else "This dataset contributes to our understanding of genomic mechanisms and biological processes."
            )

        except Exception as e:
            logger.error(f"Error generating significance summary: {e}")
            return "This dataset contributes to our understanding of genomic mechanisms and biological processes."

    def _generate_brief_summary(
        self, metadata: Dict[str, Any], query_context: Optional[str]
    ) -> str:
        """Generate brief, one-paragraph summary."""
        prompt = self._build_overview_prompt(
            metadata, query_context, brief=True
        )

        try:
            if not self.client:
                return f"{metadata.get('accession', 'Dataset')}: {metadata.get('title', 'Genomics study')} using {metadata.get('platform', 'genomics technology')}."

            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a genomics expert who creates concise, "
                            "one-paragraph summaries of research datasets. "
                            "Focus on key findings and relevance."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                max_tokens=200,
                temperature=self.temperature,
            )

            content = response.choices[0].message.content
            return (
                content.strip()
                if content
                else f"{metadata.get('accession', 'Dataset')}: {metadata.get('title', 'Genomics study')} using {metadata.get('platform', 'genomics technology')}."
            )

        except Exception as e:
            logger.error(f"Error generating brief summary: {e}")
            return f"{metadata.get('accession', 'Dataset')}: {metadata.get('title', 'Genomics study')} using {metadata.get('platform', 'genomics technology')}."

    def _generate_technical_summary(self, metadata: Dict[str, Any]) -> str:
        """Generate technical details summary."""
        technical_info = []

        if metadata.get("platform"):
            technical_info.append(f"Platform: {metadata['platform']}")

        if metadata.get("sample_count"):
            technical_info.append(f"Samples: {metadata['sample_count']}")

        if metadata.get("organism"):
            technical_info.append(f"Organism: {metadata['organism']}")

        if metadata.get("submission_date"):
            technical_info.append(f"Submitted: {metadata['submission_date']}")

        return (
            " | ".join(technical_info)
            if technical_info
            else "Technical details not available"
        )

    def _build_overview_prompt(
        self,
        metadata: Dict[str, Any],
        query_context: Optional[str],
        brief: bool = False,
    ) -> str:
        """Build the prompt for overview generation."""
        context_text = (
            f" in the context of '{query_context}'" if query_context else ""
        )
        length_instruction = "1-2 sentences" if brief else "2-3 sentences"

        prompt = f"""
        Summarize this genomics dataset{context_text}:

        Dataset ID: {metadata.get('accession', 'Unknown')}
        Title: {metadata.get('title', 'No title available')}
        Type: {metadata.get('type', 'Unknown')}
        Organism: {metadata.get('organism', 'Unknown')}
        Platform: {metadata.get('platform', 'Unknown')}
        Sample Count: {metadata.get('sample_count', 0)}

        Description: {metadata.get('summary', 'No description available')[:800]}

        Provide a clear, scientific summary in {length_instruction} that explains:
        1. What biological question this study addresses
        2. The experimental approach used
        3. Why this data is valuable for research{context_text}

        Write for researchers who want to quickly understand the dataset's relevance.
        """

        return prompt

    def _generate_fallback_summary(
        self, metadata: Dict[str, Any]
    ) -> Dict[str, str]:
        """Generate basic summary when LLM is not available."""
        accession = metadata.get("accession", "Unknown")
        title = metadata.get("title", "No title available")
        platform = metadata.get("platform", "unknown platform")
        sample_count = len(metadata.get("samples", []))
        organism = metadata.get("organism", "unknown organism")

        overview = (
            f"Dataset {accession} contains {sample_count} samples from {organism} "
            f"using {platform} technology. {title}"
        )

        return {
            "overview": overview,
            "methodology": f"Study conducted using {platform} on {organism} samples.",
            "technical_details": f"Platform: {platform} | Samples: {sample_count} | Organism: {organism}",
            "significance": "This dataset contributes to genomics research and understanding of biological processes.",
        }

    def summarize_batch_results(
        self, results: List[Dict[str, Any]], query: str
    ) -> Dict[str, Any]:
        """Generate summary of multiple dataset results."""
        if not results:
            return {"summary": "No datasets found for the given query."}

        # Check cache first
        cache_key = f"{query}_batch_{len(results)}"
        cached_summary = self.cache.get(
            cache_key, "batch_summary", len(results)
        )
        if cached_summary:
            logger.info(
                f"Using cached batch summary for query: {query[:50]}..."
            )
            return cached_summary

        # Extract key statistics
        total_datasets = len(results)
        organisms = set()
        platforms = set()
        types = set()
        total_samples = 0

        for result in results:
            metadata = result.get("metadata", {})
            if metadata.get("organism"):
                organisms.add(metadata["organism"])
            if metadata.get("platform"):
                platforms.add(metadata["platform"])
            if metadata.get("type"):
                types.add(metadata["type"])
            total_samples += len(metadata.get("samples", []))

        # Generate batch summary
        summary = {
            "query": query,
            "total_datasets": total_datasets,
            "total_samples": total_samples,
            "organisms": list(organisms),
            "platforms": list(platforms),
            "study_types": list(types),
            "overview": (
                f"Found {total_datasets} datasets with {total_samples} total samples "
                f"across {len(organisms)} organisms using {len(platforms)} different platforms."
            ),
        }

        # Cache the summary
        self.cache.set(cache_key, "batch_summary", summary, len(results))

        return summary


# Global summarization service instance
summarization_service = SummarizationService()
