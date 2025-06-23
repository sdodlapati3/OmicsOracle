"""
Natural Language Processing Foundation for OmicsOracle.

This module provides the core NLP capabilities for interpreting user prompts
and extracting biological entities and concepts.
"""

import logging
import re
from typing import Any, Dict, List, Optional, Set

try:
    import spacy

    HAS_SPACY = True
except ImportError:
    HAS_SPACY = False

try:
    import scispacy  # noqa: F401

    HAS_SCISPACY = True
except ImportError:
    HAS_SCISPACY = False

from ..core.config import Config
from ..core.exceptions import ModelLoadError, NLPProcessingError

logger = logging.getLogger(__name__)


class PromptInterpreter:
    """
    Interprets natural language prompts for genomics data queries.

    Uses spaCy + SciSpaCy for biomedical named entity recognition
    and intent classification.
    """

    def __init__(self, config: Optional[Config] = None):
        """Initialize the prompt interpreter."""
        self.config = config or Config()
        self.nlp_model = None
        self._initialize_models()

    def _initialize_models(self) -> None:
        """Initialize NLP models."""
        if not HAS_SPACY:
            logger.warning(
                "spaCy not available - install with: pip install spacy"
            )
            return

        if not HAS_SCISPACY:
            logger.warning(
                "SciSpaCy not available - install with: pip install scispacy"
            )

        try:
            # Try to load SciSpaCy model first (biomedical focus)
            if HAS_SCISPACY:
                try:
                    self.nlp_model = spacy.load("en_core_sci_sm")
                    logger.info("Loaded SciSpaCy biomedical model")
                except OSError:
                    logger.warning(
                        "SciSpaCy model not found. Install with: "
                        "pip install https://s3-us-west-2.amazonaws.com/"
                        "ai2-s2-scispacy/releases/v0.5.4/"
                        "en_core_sci_sm-0.5.4.tar.gz"
                    )
                    # Fall back to standard spaCy
                    self.nlp_model = spacy.load("en_core_web_sm")
                    logger.info("Loaded standard spaCy model as fallback")
            else:
                # Use standard spaCy model
                self.nlp_model = spacy.load("en_core_web_sm")
                logger.info("Loaded standard spaCy model")

        except OSError as e:
            logger.error("Failed to load NLP models: %s", str(e))
            logger.info(
                "Install spaCy models with: "
                "python -m spacy download en_core_web_sm"
            )
            raise ModelLoadError(
                "NLP models not available. Please install spaCy models."
            ) from e

    def extract_entities(self, text: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        Extract biomedical entities from text.

        Args:
            text: Input text to analyze

        Returns:
            Dictionary of entity types and their details
        """
        if not self.nlp_model:
            raise NLPProcessingError("NLP model not initialized")

        try:
            doc = self.nlp_model(text)

            entities = {
                "genes": [],
                "diseases": [],
                "organisms": [],
                "tissues": [],
                "chemicals": [],
                "general": [],
            }

            for ent in doc.ents:
                entity_info = {
                    "text": ent.text,
                    "label": ent.label_,
                    "start": ent.start_char,
                    "end": ent.end_char,
                    "confidence": getattr(ent, "_.confidence", 1.0),
                }

                # Categorize biomedical entities
                if ent.label_ in ["GENE", "PROTEIN"]:
                    entities["genes"].append(entity_info)
                elif ent.label_ in ["DISEASE", "SYMPTOM"]:
                    entities["diseases"].append(entity_info)
                elif ent.label_ in ["ORGANISM", "SPECIES"]:
                    entities["organisms"].append(entity_info)
                elif ent.label_ in ["TISSUE", "ORGAN", "CELL_TYPE"]:
                    entities["tissues"].append(entity_info)
                elif ent.label_ in ["CHEMICAL", "DRUG"]:
                    entities["chemicals"].append(entity_info)
                else:
                    entities["general"].append(entity_info)

            return entities

        except Exception as e:
            logger.error("Error extracting entities: %s", str(e))
            raise NLPProcessingError(
                f"Failed to extract entities: {str(e)}"
            ) from e

    def classify_intent(self, text: str) -> Dict[str, Any]:
        """
        Classify the intent of a user prompt.

        Args:
            text: User prompt text

        Returns:
            Dictionary with intent classification and confidence
        """
        text_lower = text.lower()

        # Define intent patterns with weights
        intent_patterns = {
            "search": [
                r"find|search|look for|get|retrieve",
            ],
            "summarize": [
                r"summarize|summary|describe|explain",
                r"what is|tell me about|information about|about",
            ],
            "compare": [
                r"compare|difference|versus|vs|against",
                r"similarity|similar|related",
            ],
            "analyze": [
                r"analyze|analysis|statistical|stats",
                r"correlation|pattern|trend",
            ],
            "download": [
                r"download|export|save|extract",
                # r"file|format|csv|json",  # Removed generic words
            ],
        }

        intent_scores = {}

        for intent, patterns in intent_patterns.items():
            score = 0
            for pattern in patterns:
                matches = len(re.findall(pattern, text_lower))
                score += matches

            if score > 0:
                intent_scores[intent] = score / len(patterns)

        if not intent_scores:
            return {"intent": "unknown", "confidence": 0.0}

        # Get highest scoring intent
        best_intent = max(intent_scores.items(), key=lambda x: x[1])

        return {
            "intent": best_intent[0],
            "confidence": best_intent[1],
            "all_scores": intent_scores,
        }

    def extract_geo_identifiers(self, text: str) -> List[str]:
        """
        Extract GEO series identifiers from text.

        Args:
            text: Text to search for GEO IDs

        Returns:
            List of found GEO series IDs
        """
        # Pattern for GEO series IDs (GSE followed by digits)
        geo_pattern = r"GSE\d+"

        geo_ids = re.findall(geo_pattern, text, re.IGNORECASE)

        # Normalize to uppercase
        return [geo_id.upper() for geo_id in geo_ids]

    def parse_search_query(self, text: str) -> Dict[str, Any]:
        """
        Parse a search query into structured components.

        Args:
            text: Natural language search query

        Returns:
            Structured query components
        """
        entities = self.extract_entities(text)
        intent = self.classify_intent(text)
        geo_ids = self.extract_geo_identifiers(text)

        # Extract key terms for search
        search_terms = []

        # Add entity text as search terms
        for entity_list in entities.values():
            for entity in entity_list:
                if entity["text"].lower() not in ["the", "and", "or", "of"]:
                    search_terms.append(entity["text"])

        # Remove duplicates while preserving order
        search_terms = list(dict.fromkeys(search_terms))

        return {
            "intent": intent,
            "entities": entities,
            "geo_ids": geo_ids,
            "search_terms": search_terms,
            "original_text": text,
        }

    def is_available(self) -> bool:
        """Check if NLP models are available."""
        return self.nlp_model is not None

    def get_model_info(self) -> Dict[str, Any]:
        """Get information about loaded models."""
        if not self.nlp_model:
            return {"status": "not_loaded", "models": []}

        model_info = {
            "status": "loaded",
            "model_name": self.nlp_model.meta.get("name", "unknown"),
            "version": self.nlp_model.meta.get("version", "unknown"),
            "language": self.nlp_model.meta.get("lang", "en"),
            "has_scispacy": HAS_SCISPACY,
            "has_spacy": HAS_SPACY,
        }

        return model_info


class BiologicalSynonymMapper:
    """
    Maps biological terms to their synonyms and standard identifiers.

    Provides normalization of biological entity names for better search.
    """

    def __init__(self) -> None:
        """Initialize the synonym mapper."""
        self._init_synonym_maps()

    def _init_synonym_maps(self) -> None:
        """Initialize basic synonym mappings."""
        # Basic gene synonyms (can be expanded with external databases)
        self.gene_synonyms = {
            "brca1": ["breast cancer 1", "brca-1", "brcaa1"],
            "brca2": ["breast cancer 2", "brca-2", "brcaa2"],
            "tp53": ["tumor protein p53", "p53", "tp-53"],
            "egfr": ["epidermal growth factor receptor", "egf receptor"],
            "her2": ["human epidermal growth factor receptor 2", "erbb2"],
        }

        # Disease synonyms
        self.disease_synonyms = {
            "breast cancer": ["breast carcinoma", "mammary cancer", "bc"],
            "lung cancer": ["lung carcinoma", "pulmonary cancer", "lc"],
            "diabetes": ["diabetes mellitus", "dm"],
            "alzheimer": ["alzheimer's disease", "ad", "dementia"],
        }

        # Organism synonyms
        self.organism_synonyms = {
            "human": ["homo sapiens", "h. sapiens", "hsa"],
            "mouse": ["mus musculus", "m. musculus", "mmu"],
            "rat": ["rattus norvegicus", "r. norvegicus", "rno"],
        }

    def get_synonyms(self, term: str, entity_type: str = "general") -> Set[str]:
        """
        Get synonyms for a biological term.

        Args:
            term: Input term
            entity_type: Type of entity (gene, disease, organism)

        Returns:
            Set of synonyms including the original term
        """
        term_lower = term.lower()
        synonyms = {term}  # Include original term

        if entity_type == "gene" and term_lower in self.gene_synonyms:
            synonyms.update(self.gene_synonyms[term_lower])
        elif entity_type == "disease" and term_lower in self.disease_synonyms:
            synonyms.update(self.disease_synonyms[term_lower])
        elif entity_type == "organism" and term_lower in self.organism_synonyms:
            synonyms.update(self.organism_synonyms[term_lower])
        else:
            # Check all categories
            for synonym_dict in [
                self.gene_synonyms,
                self.disease_synonyms,
                self.organism_synonyms,
            ]:
                if term_lower in synonym_dict:
                    synonyms.update(synonym_dict[term_lower])

        return synonyms

    def normalize_term(self, term: str, entity_type: str = "general") -> str:
        """
        Normalize a biological term to its standard form.

        Args:
            term: Input term
            entity_type: Type of entity

        Returns:
            Normalized term
        """
        term_lower = term.lower()

        # Check if term is a synonym and return the canonical form
        if entity_type == "gene":
            for canonical, synonyms in self.gene_synonyms.items():
                if term_lower in synonyms or term_lower == canonical:
                    return canonical.upper()
        elif entity_type == "disease":
            for canonical, synonyms in self.disease_synonyms.items():
                if term_lower in synonyms or term_lower == canonical:
                    return canonical.title()
        elif entity_type == "organism":
            for canonical, synonyms in self.organism_synonyms.items():
                if term_lower in synonyms or term_lower == canonical:
                    return canonical.title()

        # Return original term if no normalization found
        return term
