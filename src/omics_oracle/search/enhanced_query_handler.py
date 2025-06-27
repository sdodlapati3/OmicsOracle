"""
Enhanced search query handler for OmicsOracle

This module improves search handling for complex, multi-part queries by breaking them
down into components and performing semantic search with better query understanding.
"""

import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class BiomedicalSynonymExpander:
    """Expands biomedical terms to include common synonyms for better search."""

    def __init__(self):
        """Initialize the synonym expander with common biomedical term mappings."""
        self.disease_synonyms = {
            "cancer": [
                "tumor",
                "tumour",
                "neoplasm",
                "malignancy",
                "carcinoma",
            ],
            "liver cancer": [
                "hepatocellular carcinoma",
                "HCC",
                "hepatic cancer",
            ],
            "breast cancer": [
                "mammary carcinoma",
                "breast tumor",
                "mammary neoplasm",
            ],
            "lung cancer": [
                "pulmonary carcinoma",
                "lung adenocarcinoma",
                "NSCLC",
                "SCLC",
            ],
            "diabetes": [
                "diabetes mellitus",
                "T1D",
                "T2D",
                "type 1 diabetes",
                "type 2 diabetes",
                "diabetic",
            ],
            "alzheimer": [
                "alzheimer's disease",
                "AD",
                "dementia",
                "neurodegenerative",
            ],
            "parkinson": ["parkinson's disease", "PD", "neurodegenerative"],
            "covid": ["covid-19", "sars-cov-2", "coronavirus", "covid19"],
            "obesity": ["metabolic syndrome", "adiposity", "overweight"],
            "arthritis": [
                "rheumatoid arthritis",
                "RA",
                "inflammatory arthritis",
                "osteoarthritis",
            ],
            "inflammation": ["inflammatory", "immune response", "autoimmune"],
        }

        self.tissue_synonyms = {
            "liver": ["hepatic", "hepatocyte", "hepatocytes", "hepatocellular"],
            "brain": [
                "neural",
                "neuron",
                "neurons",
                "neuronal",
                "glial",
                "cerebral",
                "cortex",
                "hippocampus",
            ],
            "heart": [
                "cardiac",
                "myocardium",
                "myocardial",
                "cardiomyocyte",
                "cardiomyocytes",
            ],
            "kidney": ["renal", "nephron", "nephric", "nephrology"],
            "lung": [
                "pulmonary",
                "airway",
                "alveolar",
                "bronchial",
                "respiratory",
            ],
            "blood": [
                "plasma",
                "serum",
                "peripheral blood",
                "PBMC",
                "leukocyte",
            ],
            "muscle": [
                "muscular",
                "myocyte",
                "myocytes",
                "skeletal muscle",
                "myofiber",
            ],
            "pancreas": [
                "pancreatic",
                "islet",
                "islets",
                "beta cell",
                "beta cells",
            ],
            "skin": ["dermal", "epidermal", "dermis", "epidermis", "cutaneous"],
            "gut": [
                "intestine",
                "intestinal",
                "colon",
                "colonic",
                "gastrointestinal",
                "GI",
            ],
            "adipose": [
                "fat",
                "adipocyte",
                "adipocytes",
                "fat tissue",
                "white adipose",
            ],
            "bone": [
                "osseous",
                "skeletal",
                "osteoblast",
                "osteoclast",
                "marrow",
                "bone marrow",
            ],
        }

        self.organism_synonyms = {
            "human": [
                "homo sapiens",
                "patient",
                "patients",
                "human subjects",
                "people",
            ],
            "mouse": ["mice", "mus musculus", "murine"],
            "rat": ["rats", "rattus norvegicus", "rodent"],
            "zebrafish": ["danio rerio", "zebra fish", "zebrafish embryo"],
            "drosophila": [
                "fruit fly",
                "fruit flies",
                "fly",
                "flies",
                "drosophila melanogaster",
            ],
            "arabidopsis": [
                "plant",
                "plants",
                "arabidopsis thaliana",
                "thale cress",
            ],
        }

        self.data_type_synonyms = {
            "RNA-seq": [
                "RNAseq",
                "RNA sequencing",
                "transcriptome sequencing",
                "mRNA-seq",
            ],
            "microarray": [
                "array",
                "chip",
                "gene chip",
                "expression array",
                "oligonucleotide array",
            ],
            "gene expression": [
                "expression",
                "transcript",
                "transcription",
                "mRNA expression",
            ],
            "methylation": [
                "DNA methylation",
                "methylome",
                "epigenetic",
                "epigenome",
                "methylation array",
            ],
            "ChIP-seq": [
                "ChIPseq",
                "chromatin immunoprecipitation",
                "binding",
                "ChIP",
            ],
            "proteomics": [
                "proteome",
                "mass spec",
                "mass spectrometry",
                "protein expression",
            ],
            "single cell": [
                "scRNA-seq",
                "single-cell",
                "sc-RNA-seq",
                "single cell transcriptomics",
            ],
            "genomics": [
                "genome",
                "genomic",
                "whole genome",
                "exome",
                "WGS",
                "WES",
            ],
        }

    def expand_term(self, term: str, category: str) -> Set[str]:
        """
        Expand a biomedical term with its synonyms.

        Args:
            term: The term to expand
            category: The category of the term (disease, tissue, organism, data_type)

        Returns:
            Set of the original term and its synonyms
        """
        if not term:
            return set()

        term = term.lower()
        synonyms = set([term])  # Always include the original term

        # Choose the right synonym dictionary
        if category == "disease":
            synonym_dict = self.disease_synonyms
        elif category == "tissue":
            synonym_dict = self.tissue_synonyms
        elif category == "organism":
            synonym_dict = self.organism_synonyms
        elif category == "data_type":
            synonym_dict = self.data_type_synonyms
        else:
            return synonyms

        # Direct lookup - exact match
        for base_term, term_synonyms in synonym_dict.items():
            if term == base_term or term in term_synonyms:
                synonyms.update([base_term] + term_synonyms)

        # Partial match - if term is contained in a longer key or synonym
        for base_term, term_synonyms in synonym_dict.items():
            if term in base_term:
                synonyms.add(base_term)
            for syn in term_synonyms:
                if term in syn:
                    synonyms.add(syn)

        return synonyms

    def expand_query_components(
        self, components: Dict[str, Optional[str]]
    ) -> Dict[str, Set[str]]:
        """
        Expand all components in a parsed query with synonyms.

        Args:
            components: Dictionary of query components

        Returns:
            Dictionary of expanded components with sets of synonyms
        """
        expanded = {}

        for category in ["disease", "tissue", "organism", "data_type"]:
            if components.get(category):
                expanded[category] = self.expand_term(
                    components[category], category
                )
            else:
                expanded[category] = set()

        return expanded


class QueryParser:
    """Parse complex queries into structured components for better search."""

    def __init__(self):
        """Initialize the query parser with patterns for common biomedical entities."""
        # Define patterns for common biomedical concepts
        self.patterns = {
            "organism": [
                r"(?:human|homo sapiens|patient|patients)",
                r"(?:mouse|mice|mus musculus)",
                r"(?:rat|rats|rattus norvegicus)",
                r"(?:zebrafish|danio rerio)",
                r"(?:drosophila|fruit fly|flies)",
                r"(?:arabidopsis|plant|plants)",
            ],
            "disease": [
                r"(?:cancer|carcinoma|tumor|tumour|neoplasm)",
                r"(?:diabetes|diabetic)",
                r"(?:alzheimer|parkinson|neurodegenerative)",
                r"(?:arthritis|inflammatory|inflammation)",
                r"(?:infection|infectious|viral|bacterial)",
                r"(?:obesity|metabolic syndrome)",
                r"(?:covid|covid-19|sars-cov-2|coronavirus)",
            ],
            "tissue": [
                r"(?:liver|hepatic|hepatocyte)",
                r"(?:brain|neural|neuron|glial)",
                r"(?:heart|cardiac|myocardial)",
                r"(?:kidney|renal|nephron)",
                r"(?:lung|pulmonary|airway)",
                r"(?:blood|serum|plasma)",
                r"(?:muscle|muscular|myocyte)",
                r"(?:pancreas|pancreatic|islet)",
                r"(?:skin|dermal|epidermal)",
                r"(?:gut|intestine|intestinal|colon)",
            ],
            "data_type": [
                r"(?:RNA-seq|RNAseq|transcriptome|transcriptomic)",
                r"(?:microarray|array|chip)",
                r"(?:methylation|epigenetic|epigenome)",
                r"(?:ChIP-seq|ChIPseq|binding)",
                r"(?:proteom|proteomics|mass spec)",
                r"(?:single cell|scRNA-seq|single-cell)",
                r"(?:gene expression|expression)",
            ],
        }

        # Initialize synonym expander
        self.synonym_expander = BiomedicalSynonymExpander()

    def parse_query(self, query: str) -> Dict[str, Optional[str]]:
        """Parse a complex query into components for structured search."""
        query = query.lower()
        components = {
            "organism": None,
            "disease": None,
            "tissue": None,
            "data_type": None,
            "original_query": query,
        }

        # Extract components using patterns
        for component, patterns in self.patterns.items():
            for pattern in patterns:
                if re.search(pattern, query, re.IGNORECASE):
                    match = re.search(pattern, query, re.IGNORECASE)
                    if match:
                        components[component] = match.group(0)
                        break

        logger.info(f"Parsed query '{query}' into components: {components}")
        return components

    def generate_alternative_queries(
        self, components: Dict[str, Optional[str]]
    ) -> List[str]:
        """Generate alternative simpler queries based on the parsed components."""
        alternative_queries = []

        # Expand components with synonyms
        expanded = self.synonym_expander.expand_query_components(components)

        # Use component combinations for queries
        # Start with just the disease or data type - most likely to get results
        if expanded["disease"]:
            alternative_queries.extend(list(expanded["disease"]))

        if expanded["data_type"]:
            alternative_queries.extend(list(expanded["data_type"]))

        # Add data type + disease/tissue queries (most likely to return results)
        for data_type in expanded["data_type"]:
            for disease in expanded["disease"]:
                alternative_queries.append(f"{data_type} {disease}")

        for data_type in expanded["data_type"]:
            for tissue in expanded["tissue"]:
                alternative_queries.append(f"{data_type} {tissue}")

        # Add organism + disease/tissue queries
        for organism in expanded["organism"]:
            for disease in expanded["disease"]:
                alternative_queries.append(f"{organism} {disease}")

        for organism in expanded["organism"]:
            for tissue in expanded["tissue"]:
                alternative_queries.append(f"{organism} {tissue}")

        # Add data type + organism queries
        for data_type in expanded["data_type"]:
            for organism in expanded["organism"]:
                alternative_queries.append(f"{data_type} {organism}")

        # Add tissue + disease combinations
        for tissue in expanded["tissue"]:
            for disease in expanded["disease"]:
                alternative_queries.append(f"{tissue} {disease}")

        # More specific combinations (3 terms)
        for data_type in expanded["data_type"]:
            for disease in expanded["disease"]:
                for organism in expanded["organism"]:
                    alternative_queries.append(
                        f"{data_type} {disease} {organism}"
                    )

        for data_type in expanded["data_type"]:
            for tissue in expanded["tissue"]:
                for organism in expanded["organism"]:
                    alternative_queries.append(
                        f"{data_type} {tissue} {organism}"
                    )

        # Remove duplicates and empty queries
        alternative_queries = [
            q for q in list(set(alternative_queries)) if q.strip()
        ]

        # Limit the number of alternative queries to avoid excessive searches
        if len(alternative_queries) > 10:
            # Prioritize queries with more components
            alternative_queries = sorted(
                alternative_queries, key=lambda q: len(q.split()), reverse=True
            )[:10]

        logger.info(
            f"Generated {len(alternative_queries)} alternative queries: {alternative_queries}"
        )
        return alternative_queries

    def extract_query_components(self, query: str) -> List[Dict[str, Any]]:
        """
        Extract biomedical components from a query string.

        Args:
            query: The query string to analyze

        Returns:
            List of extracted components with their types and metadata
        """
        components = []

        # Extract diseases
        diseases = self._extract_diseases(query)
        for disease in diseases:
            components.append(
                {"type": "disease", "value": disease, "confidence": 0.9}
            )

        # Extract tissues
        tissues = self._extract_tissues(query)
        for tissue in tissues:
            components.append(
                {"type": "tissue", "value": tissue, "confidence": 0.85}
            )

        # Extract organisms
        organisms = self._extract_organisms(query)
        for organism in organisms:
            components.append(
                {"type": "organism", "value": organism, "confidence": 0.8}
            )

        # Extract data types
        data_types = self._extract_data_types(query)
        for data_type in data_types:
            components.append(
                {"type": "data_type", "value": data_type, "confidence": 0.9}
            )

        return components

    def _extract_diseases(self, query: str) -> List[str]:
        """Extract disease terms from the query."""
        diseases = []

        # Check each disease keyword
        for disease, synonyms in self.synonym_expander.disease_synonyms.items():
            # Check the primary disease term
            if disease.lower() in query.lower():
                diseases.append(disease)
                continue

            # Check synonyms
            for synonym in synonyms:
                if synonym.lower() in query.lower():
                    diseases.append(disease)
                    break

        return diseases

    def _extract_tissues(self, query: str) -> List[str]:
        """Extract tissue terms from the query."""
        tissues = []

        # Check each tissue keyword
        for tissue, synonyms in self.synonym_expander.tissue_synonyms.items():
            # Check the primary tissue term
            if tissue.lower() in query.lower():
                tissues.append(tissue)
                continue

            # Check synonyms
            for synonym in synonyms:
                if synonym.lower() in query.lower():
                    tissues.append(tissue)
                    break

        return tissues

    def _extract_organisms(self, query: str) -> List[str]:
        """Extract organism terms from the query."""
        organisms = []

        # Check each organism keyword
        for (
            organism,
            synonyms,
        ) in self.synonym_expander.organism_synonyms.items():
            # Check the primary organism term
            if organism.lower() in query.lower():
                organisms.append(organism)
                continue

            # Check synonyms
            for synonym in synonyms:
                if synonym.lower() in query.lower():
                    organisms.append(organism)
                    break

        return organisms

    def _extract_data_types(self, query: str) -> List[str]:
        """Extract data type terms from the query."""
        data_types = []

        # Common data type terms in omics research
        data_type_keywords = {
            "RNA-seq": [
                "RNA sequencing",
                "RNA-sequencing",
                "transcriptome",
                "transcriptomics",
            ],
            "microarray": ["gene expression array", "expression array"],
            "ChIP-seq": ["ChIP sequencing", "chromatin immunoprecipitation"],
            "ATAC-seq": [
                "assay for transposase-accessible chromatin",
                "chromatin accessibility",
            ],
            "proteomics": [
                "protein expression",
                "protein profiling",
                "mass spectrometry",
            ],
            "methylation": ["DNA methylation", "methylome", "epigenetics"],
            "single cell": ["single-cell", "scRNA-seq", "single cell RNA-seq"],
            "exome": ["exome sequencing", "whole exome"],
            "genome": ["genome sequencing", "whole genome", "WGS"],
            "metabolomics": ["metabolite profiling", "metabolome"],
        }

        # Check for data type terms
        for data_type, synonyms in data_type_keywords.items():
            # Check primary term
            if data_type.lower() in query.lower():
                data_types.append(data_type)
                continue

            # Check synonyms
            for synonym in synonyms:
                if synonym.lower() in query.lower():
                    data_types.append(data_type)
                    break

        return data_types


async def perform_multi_strategy_search(
    pipeline, query: str, max_results: int = 10
) -> Tuple[List[str], Dict[str, Any]]:
    """
    Perform a multi-strategy search that breaks down complex queries and tries multiple approaches.

    Args:
        pipeline: The OmicsOracle pipeline instance
        query: The original search query
        max_results: Maximum number of results to return

    Returns:
        Tuple of (geo_ids, metadata)
    """
    logger.info(f"Performing multi-strategy search for: '{query}'")

    # Parse the query into components
    parser = QueryParser()
    components = parser.parse_query(query)

    # Get expanded components
    expanded_components = parser.synonym_expander.expand_query_components(
        components
    )

    # Try the original query first
    try:
        logger.info(f"Trying original query: '{query}'")
        result = await pipeline.process_query(query, max_results=max_results)

        if result and hasattr(result, "geo_ids") and result.geo_ids:
            logger.info(
                f"Original query succeeded with {len(result.geo_ids)} results"
            )
            return result.geo_ids, {
                "metadata": result.metadata
                if hasattr(result, "metadata")
                else {},
                "ai_summaries": result.ai_summaries
                if hasattr(result, "ai_summaries")
                else {},
                "components": components,
                "expanded_components": {
                    k: list(v) for k, v in expanded_components.items()
                },
                "search_strategy": "original",
                "query_used": query,
            }
    except Exception as e:
        logger.warning(f"Original query failed: {e}")

    # If original query returns no results, try alternative queries
    alternative_queries = parser.generate_alternative_queries(components)

    # Track tried queries to avoid duplicates
    tried_queries = {query}

    for alt_query in alternative_queries:
        # Skip if we've already tried this query
        if alt_query in tried_queries:
            continue

        tried_queries.add(alt_query)

        try:
            logger.info(f"Trying alternative query: '{alt_query}'")
            result = await pipeline.process_query(
                alt_query, max_results=max_results
            )

            if result and hasattr(result, "geo_ids") and result.geo_ids:
                logger.info(
                    f"Alternative query '{alt_query}' succeeded with {len(result.geo_ids)} results"
                )
                return result.geo_ids, {
                    "metadata": result.metadata
                    if hasattr(result, "metadata")
                    else {},
                    "ai_summaries": result.ai_summaries
                    if hasattr(result, "ai_summaries")
                    else {},
                    "components": components,
                    "expanded_components": {
                        k: list(v) for k, v in expanded_components.items()
                    },
                    "search_strategy": "alternative",
                    "query_used": alt_query,
                    "original_query": query,
                }
        except Exception as e:
            logger.warning(f"Alternative query '{alt_query}' failed: {e}")

    # If no results from any strategy, return empty results
    logger.warning(f"No results found for any query strategy")
    return [], {
        "components": components,
        "expanded_components": {
            k: list(v) for k, v in expanded_components.items()
        },
        "search_strategy": "failed",
        "error": "No results found for any query strategy",
    }


class EnhancedQueryHandler:
    """
    Enhanced query handler for OmicsOracle search.

    This class breaks down complex, multi-part queries into components,
    expands biomedical terms with synonyms, and provides better
    semantic understanding of search queries.
    """

    def __init__(self):
        """Initialize the enhanced query handler."""
        self.synonym_expander = BiomedicalSynonymExpander()

    def extract_components(self, query: str) -> Dict[str, List[str]]:
        """
        Extract key components from a query.

        Args:
            query: The search query string

        Returns:
            A dictionary of extracted components by category
        """
        components = {
            "diseases": [],
            "tissues": [],
            "organisms": [],
            "data_types": [],
            "analysis_methods": [],
        }

        # Extract disease terms
        for disease, synonyms in self.synonym_expander.disease_synonyms.items():
            if disease.lower() in query.lower():
                components["diseases"].append(disease)
            else:
                for synonym in synonyms:
                    if synonym.lower() in query.lower():
                        components["diseases"].append(disease)
                        break

        # Extract tissue terms
        for tissue, synonyms in self.synonym_expander.tissue_synonyms.items():
            if tissue.lower() in query.lower():
                components["tissues"].append(tissue)
            else:
                for synonym in synonyms:
                    if synonym.lower() in query.lower():
                        components["tissues"].append(tissue)
                        break

        # Extract organism terms
        for (
            organism,
            synonyms,
        ) in self.synonym_expander.organism_synonyms.items():
            if organism.lower() in query.lower():
                components["organisms"].append(organism)
            else:
                for synonym in synonyms:
                    if synonym.lower() in query.lower():
                        components["organisms"].append(organism)
                        break

        # Extract data type terms
        for (
            data_type,
            synonyms,
        ) in self.synonym_expander.data_type_synonyms.items():
            if data_type.lower() in query.lower():
                components["data_types"].append(data_type)
            else:
                for synonym in synonyms:
                    if synonym.lower() in query.lower():
                        components["data_types"].append(data_type)
                        break

        # Extract analysis method terms
        for (
            method,
            synonyms,
        ) in self.synonym_expander.analysis_method_synonyms.items():
            if method.lower() in query.lower():
                components["analysis_methods"].append(method)
            else:
                for synonym in synonyms:
                    if synonym.lower() in query.lower():
                        components["analysis_methods"].append(method)
                        break

        return components

    def enhance_query(self, query: str) -> str:
        """
        Enhance a query by expanding terms and improving structure.

        Args:
            query: The original search query

        Returns:
            An enhanced query for better search results
        """
        components = self.extract_components(query)
        enhanced_parts = []

        # Add diseases with synonyms
        for disease in components["diseases"]:
            disease_terms = [
                disease
            ] + self.synonym_expander.disease_synonyms.get(disease, [])
            enhanced_parts.append(f"({' OR '.join(disease_terms)})")

        # Add tissues with synonyms
        for tissue in components["tissues"]:
            tissue_terms = [tissue] + self.synonym_expander.tissue_synonyms.get(
                tissue, []
            )
            enhanced_parts.append(f"({' OR '.join(tissue_terms)})")

        # Add organisms with synonyms
        for organism in components["organisms"]:
            organism_terms = [
                organism
            ] + self.synonym_expander.organism_synonyms.get(organism, [])
            enhanced_parts.append(f"({' OR '.join(organism_terms)})")

        # Add data types with synonyms
        for data_type in components["data_types"]:
            data_type_terms = [
                data_type
            ] + self.synonym_expander.data_type_synonyms.get(data_type, [])
            enhanced_parts.append(f"({' OR '.join(data_type_terms)})")

        # Add analysis methods with synonyms
        for method in components["analysis_methods"]:
            method_terms = [
                method
            ] + self.synonym_expander.analysis_method_synonyms.get(method, [])
            enhanced_parts.append(f"({' OR '.join(method_terms)})")

        # If we extracted components, use them to build an enhanced query
        if enhanced_parts:
            enhanced_query = " AND ".join(enhanced_parts)
            return enhanced_query

        # If no components extracted, return original query
        return query
