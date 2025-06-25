"""
Improved Search Service for Complex Biomedical Queries

This service enhances search capabilities by:
1. Better entity recognition and categorization
2. Smart query expansion and synonym management
3. Multi-strategy search with fallback approaches
4. Query optimization for better results
"""

import asyncio
import logging
from typing import Any, Dict, List, Tuple

logger = logging.getLogger(__name__)


class ImprovedSearchService:
    """Enhanced search service for complex biomedical queries."""

    def __init__(self, geo_client, biomedical_ner, synonym_mapper):
        """Initialize the improved search service."""
        self.geo_client = geo_client
        self.biomedical_ner = biomedical_ner
        self.synonym_mapper = synonym_mapper

        # Enhanced experimental technique patterns
        self.experimental_techniques = {
            "dna-methylation": [
                "methylation",
                "bisulfite",
                "WGBS",
                "RRBS",
                "methylome",
            ],
            "methylation": ["bisulfite", "WGBS", "RRBS", "methylome", "CpG"],
            "rna-seq": ["RNA sequencing", "transcriptome", "gene expression"],
            "chip-seq": [
                "chromatin immunoprecipitation",
                "transcription factor",
            ],
            "atac-seq": ["chromatin accessibility", "open chromatin"],
            "single-cell": ["scRNA-seq", "single cell", "sc-seq"],
            "proteomics": ["mass spectrometry", "protein expression"],
            "genomics": ["whole genome", "DNA sequencing", "variant calling"],
        }

        # Disease-tissue associations for better search
        self.disease_tissue_associations = {
            "cancer": ["tumor", "carcinoma", "neoplasm", "malignant"],
            "brain cancer": [
                "glioma",
                "glioblastoma",
                "astrocytoma",
                "meningioma",
            ],
            "breast cancer": [
                "mammary",
                "ductal carcinoma",
                "lobular carcinoma",
            ],
            "lung cancer": ["pulmonary", "adenocarcinoma", "squamous cell"],
            "alzheimer": ["neurodegeneration", "dementia", "amyloid"],
            "parkinson": ["dopamine", "substantia nigra", "lewy body"],
        }

    def enhance_entity_extraction(
        self, query: str
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Enhanced entity extraction with better categorization."""
        # Get initial entities
        entities = self.biomedical_ner.extract_biomedical_entities(query)

        # Enhance with manual patterns for complex terms
        enhanced_entities = entities.copy()
        query_lower = query.lower()

        # Check for experimental techniques that might be missed
        for technique, synonyms in self.experimental_techniques.items():
            if technique in query_lower or any(
                syn.lower() in query_lower for syn in synonyms
            ):
                if not enhanced_entities.get("experimental_techniques"):
                    enhanced_entities["experimental_techniques"] = []

                # Add the technique if not already present
                existing_texts = {
                    e["text"].lower()
                    for e in enhanced_entities["experimental_techniques"]
                }
                if technique not in existing_texts:
                    enhanced_entities["experimental_techniques"].append(
                        {
                            "text": technique,
                            "label": "TECHNIQUE",
                            "start": query_lower.find(technique),
                            "end": query_lower.find(technique) + len(technique),
                            "confidence": 0.9,
                        }
                    )

        # Move misclassified items from 'general' to appropriate categories
        if "general" in enhanced_entities:
            general_items = enhanced_entities["general"][:]
            for item in general_items:
                text_lower = item["text"].lower()
                moved = False

                # Check if it's actually an experimental technique
                for technique, synonyms in self.experimental_techniques.items():
                    if text_lower == technique or text_lower in [
                        s.lower() for s in synonyms
                    ]:
                        if "experimental_techniques" not in enhanced_entities:
                            enhanced_entities["experimental_techniques"] = []
                        enhanced_entities["experimental_techniques"].append(
                            {**item, "label": "TECHNIQUE"}
                        )
                        enhanced_entities["general"].remove(item)
                        moved = True
                        break

                if not moved:
                    # Check for tissue/anatomy terms
                    anatomy_terms = [
                        "brain",
                        "liver",
                        "heart",
                        "lung",
                        "kidney",
                        "tissue",
                    ]
                    if any(term in text_lower for term in anatomy_terms):
                        if "tissues" not in enhanced_entities:
                            enhanced_entities["tissues"] = []
                        enhanced_entities["tissues"].append(
                            {**item, "label": "TISSUE"}
                        )
                        enhanced_entities["general"].remove(item)

        return enhanced_entities

    def create_search_strategies(
        self, entities: Dict[str, List[Dict[str, Any]]]
    ) -> List[Tuple[str, str]]:
        """Create multiple search strategies for better coverage."""
        strategies = []

        # Extract entity texts by category
        techniques = [
            e["text"] for e in entities.get("experimental_techniques", [])
        ]
        diseases = [e["text"] for e in entities.get("diseases", [])]
        organisms = [e["text"] for e in entities.get("organisms", [])]
        tissues = [e["text"] for e in entities.get("tissues", [])]

        # Strategy 1: Core technique + disease + organism
        if techniques and diseases:
            core_terms = []
            # Use primary technique
            tech_term = techniques[0].lower()
            if tech_term in self.experimental_techniques:
                core_terms.extend(
                    self.experimental_techniques[tech_term][:2]
                )  # Top 2 synonyms
            else:
                core_terms.append(tech_term)

            # Add disease terms
            disease_term = diseases[0].lower()
            core_terms.append(disease_term)
            if disease_term in self.disease_tissue_associations:
                core_terms.extend(
                    self.disease_tissue_associations[disease_term][:2]
                )

            # Add organism if present
            if organisms:
                core_terms.append(organisms[0])

            query = " ".join(core_terms)
            strategies.append(("core_technique_disease", query))

        # Strategy 2: Technique + tissue + organism
        if techniques and (tissues or organisms):
            terms = []
            tech_term = techniques[0].lower()
            if tech_term in self.experimental_techniques:
                terms.extend(self.experimental_techniques[tech_term][:2])
            else:
                terms.append(tech_term)

            if tissues:
                terms.append(tissues[0])
            if organisms:
                terms.append(organisms[0])

            query = " ".join(terms)
            strategies.append(("technique_tissue", query))

        # Strategy 3: Disease + tissue combination
        if diseases and tissues:
            terms = [diseases[0], tissues[0]]
            if organisms:
                terms.append(organisms[0])

            query = " ".join(terms)
            strategies.append(("disease_tissue", query))

        # Strategy 4: Technique only (broader search)
        if techniques:
            tech_term = techniques[0].lower()
            if tech_term in self.experimental_techniques:
                synonyms = self.experimental_techniques[tech_term]
                query = " OR ".join(synonyms[:3])  # Use OR for broader search
            else:
                query = tech_term
            strategies.append(("technique_only", query))

        # Strategy 5: Disease + organism (fallback)
        if diseases and organisms:
            query = f"{diseases[0]} {organisms[0]}"
            strategies.append(("disease_organism", query))

        return strategies

    async def search_with_multiple_strategies(
        self, query: str, max_results: int = 20
    ) -> Tuple[List[str], Dict[str, Any]]:
        """Search using multiple strategies and combine results."""

        # Enhanced entity extraction
        entities = self.enhance_entity_extraction(query)

        # Create search strategies
        strategies = self.create_search_strategies(entities)

        # If no specific strategies, fall back to original query
        if not strategies:
            strategies = [("original", query)]

        logger.info(f"Testing {len(strategies)} search strategies for: {query}")

        all_results = []
        strategy_results = {}

        # Try each strategy
        for strategy_name, search_query in strategies:
            try:
                logger.info(
                    f"Trying strategy '{strategy_name}': {search_query}"
                )
                results = await self.geo_client.search_geo_series(
                    search_query, max_results=max_results
                )

                if results:
                    strategy_results[strategy_name] = {
                        "query": search_query,
                        "count": len(results),
                        "results": results,
                    }
                    all_results.extend(results)
                    logger.info(
                        f"Strategy '{strategy_name}' found {len(results)} results"
                    )
                else:
                    logger.info(f"Strategy '{strategy_name}' found no results")

            except Exception as e:
                logger.warning(f"Strategy '{strategy_name}' failed: {e}")
                continue

        # Remove duplicates while preserving order
        unique_results = []
        seen = set()
        for result in all_results:
            if result not in seen:
                unique_results.append(result)
                seen.add(result)

        search_metadata = {
            "original_query": query,
            "enhanced_entities": entities,
            "strategies_tried": len(strategies),
            "successful_strategies": len(strategy_results),
            "strategy_details": strategy_results,
            "total_unique_results": len(unique_results),
        }

        logger.info(
            f"Combined search found {len(unique_results)} unique results from {len(strategy_results)} successful strategies"
        )

        return unique_results[:max_results], search_metadata


async def test_improved_search():
    """Test the improved search service."""
    from ..core.config import Config
    from ..geo_tools.geo_client import UnifiedGEOClient
    from ..nlp.biomedical_ner import (
        BiomedicalNER,
        EnhancedBiologicalSynonymMapper,
    )

    # Initialize components
    config = Config()
    geo_client = UnifiedGEOClient(config)
    ner = BiomedicalNER()
    synonym_mapper = EnhancedBiologicalSynonymMapper()

    # Create improved search service
    search_service = ImprovedSearchService(geo_client, ner, synonym_mapper)

    # Test queries
    test_queries = [
        "dna-methylation of cancer tissue of human brain",
        "WGBS methylation brain cancer",
        "RNA-seq breast cancer human",
        "single-cell brain development",
    ]

    for query in test_queries:
        print(f"\n=== Testing Query: {query} ===")
        try:
            (
                results,
                metadata,
            ) = await search_service.search_with_multiple_strategies(query)
            print(f"Found {len(results)} results")
            print(f"Successful strategies: {metadata['successful_strategies']}")

            for strategy, details in metadata["strategy_details"].items():
                print(
                    f"  - {strategy}: '{details['query']}' -> {details['count']} results"
                )

            if results:
                print(f"Sample results: {results[:3]}")

        except Exception as e:
            print(f"Error: {e}")

    await geo_client.close()


if __name__ == "__main__":
    asyncio.run(test_improved_search())
