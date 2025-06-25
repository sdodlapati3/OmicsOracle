"""
Query Analysis Service for OmicsOracle

This service analyzes queries to understand why they failed and generates
intelligent refinement suggestions to improve search results.
"""

import logging
import re
from collections import Counter
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class SuggestionType(Enum):
    """Types of query refinement suggestions."""

    ENTITY_SIMPLIFICATION = "entity_simplification"
    SYNONYM_SUBSTITUTION = "synonym_substitution"
    QUERY_BROADENING = "query_broadening"
    TERM_ADDITION = "term_addition"
    STRUCTURAL_MODIFICATION = "structural_modification"
    SPELLING_CORRECTION = "spelling_correction"


class QueryIssue(Enum):
    """Types of issues that can affect query performance."""

    TOO_SPECIFIC = "query_too_specific"
    RARE_ENTITIES = "contains_rare_entities"
    CONFLICTING_TERMS = "conflicting_terms"
    MISSPELLED_TERMS = "potential_misspellings"
    UNSUPPORTED_FORMAT = "unsupported_query_format"
    NO_BIOMEDICAL_ENTITIES = "no_biomedical_entities"


@dataclass
class QuerySuggestion:
    """A query refinement suggestion."""

    suggested_query: str
    suggestion_type: SuggestionType
    confidence_score: float
    explanation: str
    expected_result_count: Optional[int] = None
    original_entities: List[str] = None
    suggested_entities: List[str] = None


@dataclass
class QueryAnalysis:
    """Analysis of a query and its potential issues."""

    original_query: str
    entities_found: Dict[str, List[Dict[str, Any]]]
    complexity_score: float
    potential_issues: List[QueryIssue]
    suggested_modifications: List[str]
    entity_rarity_scores: Dict[str, float]


@dataclass
class SimilarQuery:
    """A similar query that returned good results."""

    query_text: str
    result_count: int
    success_score: float
    similarity_score: float
    common_entities: List[str]


class QueryAnalysisService:
    """
    Service for analyzing queries and generating refinement suggestions.

    This service integrates with existing NLP components to understand
    query failures and generate actionable suggestions for improvement.
    """

    def __init__(self, biomedical_ner=None, synonym_mapper=None):
        """
        Initialize the query analysis service.

        Args:
            biomedical_ner: BiomedicalNER instance for entity extraction
            synonym_mapper: SynonymMapper instance for finding alternatives
        """
        self.biomedical_ner = biomedical_ner
        self.synonym_mapper = synonym_mapper

        # Common biomedical terms that often lead to good results
        self.common_biomedical_terms = {
            "cancer",
            "tumor",
            "disease",
            "gene",
            "expression",
            "protein",
            "cell",
            "tissue",
            "human",
            "mouse",
            "brain",
            "blood",
            "rna",
            "dna",
            "sequencing",
            "microarray",
            "analysis",
            "study",
        }

        # Pattern recognition for common query structures
        self.query_patterns = {
            "technical_assay": re.compile(
                r"\b(rna-seq|microarray|chip-seq|wgbs|atac-seq)\b", re.I
            ),
            "organism": re.compile(
                r"\b(human|mouse|rat|homo sapiens|mus musculus)\b", re.I
            ),
            "tissue_type": re.compile(
                r"\b(brain|liver|heart|lung|kidney|blood|skin)\b", re.I
            ),
            "disease_terms": re.compile(
                r"\b(cancer|tumor|disease|syndrome|disorder)\b", re.I
            ),
        }

        logger.info("QueryAnalysisService initialized")

    def analyze_failed_query(
        self, query: str, result_count: int
    ) -> QueryAnalysis:
        """
        Analyze a query that returned poor results.

        Args:
            query: The original query string
            result_count: Number of results returned

        Returns:
            QueryAnalysis object with identified issues and suggestions
        """
        logger.debug(
            f"Analyzing failed query: '{query}' with {result_count} results"
        )

        # Extract entities if NER is available
        entities = {}
        if self.biomedical_ner:
            try:
                entities = self.biomedical_ner.extract_biomedical_entities(
                    query
                )
            except Exception as e:
                logger.warning(f"Entity extraction failed: {e}")

        # Calculate complexity score
        complexity_score = self._calculate_complexity_score(query, entities)

        # Identify potential issues
        issues = self._identify_query_issues(query, entities, result_count)

        # Calculate entity rarity scores
        rarity_scores = self._calculate_entity_rarity_scores(entities)

        # Generate suggested modifications
        modifications = self._generate_query_modifications(
            query, entities, issues
        )

        analysis = QueryAnalysis(
            original_query=query,
            entities_found=entities,
            complexity_score=complexity_score,
            potential_issues=issues,
            suggested_modifications=modifications,
            entity_rarity_scores=rarity_scores,
        )

        logger.debug(
            f"Query analysis completed: {len(issues)} issues identified"
        )
        return analysis

    def generate_suggestions(
        self, analysis: QueryAnalysis
    ) -> List[QuerySuggestion]:
        """
        Generate refinement suggestions based on query analysis.

        Args:
            analysis: QueryAnalysis object from analyze_failed_query

        Returns:
            List of QuerySuggestion objects ordered by confidence
        """
        suggestions = []

        # Generate different types of suggestions based on identified issues
        for issue in analysis.potential_issues:
            if issue == QueryIssue.TOO_SPECIFIC:
                suggestions.extend(
                    self._generate_broadening_suggestions(analysis)
                )
            elif issue == QueryIssue.RARE_ENTITIES:
                suggestions.extend(self._generate_synonym_suggestions(analysis))
            elif issue == QueryIssue.NO_BIOMEDICAL_ENTITIES:
                suggestions.extend(
                    self._generate_term_addition_suggestions(analysis)
                )
            elif issue == QueryIssue.MISSPELLED_TERMS:
                suggestions.extend(
                    self._generate_spelling_suggestions(analysis)
                )

        # Always try some general improvement strategies
        suggestions.extend(self._generate_simplification_suggestions(analysis))
        suggestions.extend(self._generate_structural_suggestions(analysis))

        # Sort by confidence score and remove duplicates
        suggestions = self._deduplicate_suggestions(suggestions)
        suggestions.sort(key=lambda x: x.confidence_score, reverse=True)

        # Limit to top suggestions
        return suggestions[:5]

    def find_similar_successful_queries(
        self, query: str, limit: int = 5
    ) -> List[SimilarQuery]:
        """
        Find similar queries that returned good results.

        Args:
            query: Original query to find similar queries for
            limit: Maximum number of similar queries to return

        Returns:
            List of SimilarQuery objects
        """
        # This would typically query a database of successful queries
        # For now, return some example similar queries based on common patterns

        similar_queries = []

        # Extract key terms from the query
        key_terms = self._extract_key_terms(query)

        # Generate some example similar queries (in production, this would query a database)
        example_queries = [
            ("breast cancer gene expression", 156, 0.85),
            ("lung cancer rna-seq", 89, 0.82),
            ("brain tumor microarray", 67, 0.78),
            ("diabetes gene expression human", 134, 0.76),
            ("heart disease transcriptome", 45, 0.73),
        ]

        for query_text, result_count, success_score in example_queries:
            similarity = self._calculate_query_similarity(query, query_text)
            if similarity > 0.3:  # Minimum similarity threshold
                common_entities = self._find_common_entities(query, query_text)
                similar_queries.append(
                    SimilarQuery(
                        query_text=query_text,
                        result_count=result_count,
                        success_score=success_score,
                        similarity_score=similarity,
                        common_entities=common_entities,
                    )
                )

        # Sort by combination of similarity and success
        similar_queries.sort(
            key=lambda x: x.similarity_score * x.success_score, reverse=True
        )

        return similar_queries[:limit]

    def score_query_complexity(self, query: str) -> float:
        """
        Score the complexity of a query (0.0 to 1.0, higher = more complex).

        Args:
            query: Query string to analyze

        Returns:
            Complexity score between 0.0 and 1.0
        """
        return self._calculate_complexity_score(query, {})

    # Private helper methods

    def _calculate_complexity_score(
        self, query: str, entities: Dict[str, List]
    ) -> float:
        """Calculate complexity score based on various factors."""
        score = 0.0

        # Length factor (longer queries are more complex)
        word_count = len(query.split())
        score += min(word_count / 20.0, 0.3)  # Max 0.3 for length

        # Entity density (more entities = more complex)
        total_entities = sum(
            len(entity_list) for entity_list in entities.values()
        )
        if word_count > 0:
            entity_density = total_entities / word_count
            score += min(entity_density, 0.4)  # Max 0.4 for entity density

        # Technical term factor
        technical_patterns = sum(
            1
            for pattern in self.query_patterns.values()
            if pattern.search(query)
        )
        score += min(
            technical_patterns / 10.0, 0.3
        )  # Max 0.3 for technical terms

        return min(score, 1.0)

    def _identify_query_issues(
        self, query: str, entities: Dict[str, List], result_count: int
    ) -> List[QueryIssue]:
        """Identify potential issues with the query."""
        issues = []

        # Check if query is too specific (many entities, few results)
        total_entities = sum(
            len(entity_list) for entity_list in entities.values()
        )
        if total_entities > 3 and result_count < 5:
            issues.append(QueryIssue.TOO_SPECIFIC)

        # Check for rare entities
        if self._has_rare_entities(entities):
            issues.append(QueryIssue.RARE_ENTITIES)

        # Check for lack of biomedical entities
        if total_entities == 0 and not any(
            term in query.lower() for term in self.common_biomedical_terms
        ):
            issues.append(QueryIssue.NO_BIOMEDICAL_ENTITIES)

        # Check for potential misspellings (simple heuristic)
        if self._has_potential_misspellings(query):
            issues.append(QueryIssue.MISSPELLED_TERMS)

        return issues

    def _has_rare_entities(self, entities: Dict[str, List]) -> bool:
        """Check if query contains rare biomedical entities."""
        # This is a simplified check - in production, this would use
        # frequency data from biomedical databases
        rare_indicators = ["syndrome", "mutation", "variant", "pathway"]

        for entity_list in entities.values():
            for entity in entity_list:
                entity_text = entity.get("text", "").lower()
                if any(
                    indicator in entity_text for indicator in rare_indicators
                ):
                    return True
        return False

    def _has_potential_misspellings(self, query: str) -> bool:
        """Simple heuristic to detect potential misspellings."""
        # Look for words that might be misspelled biomedical terms
        words = query.lower().split()
        suspicious_patterns = [
            r"\w*seq\w*",  # sequencing-related terms
            r"\w*cancer\w*",  # cancer-related terms
            r"\w*gene\w*",  # gene-related terms
        ]

        for word in words:
            if len(word) > 6 and not any(
                re.match(pattern, word) for pattern in suspicious_patterns
            ):
                # Very basic spell check - in production use proper spell checker
                if word not in self.common_biomedical_terms:
                    return True
        return False

    def _calculate_entity_rarity_scores(
        self, entities: Dict[str, List]
    ) -> Dict[str, float]:
        """Calculate rarity scores for extracted entities."""
        rarity_scores = {}

        for entity_type, entity_list in entities.items():
            for entity in entity_list:
                entity_text = entity.get("text", "")
                # Simple rarity scoring - in production use frequency databases
                score = 1.0  # Default to common
                if (
                    len(entity_text.split()) > 2
                ):  # Multi-word entities are often rarer
                    score = 0.6
                if any(
                    rare_term in entity_text.lower()
                    for rare_term in ["syndrome", "mutation", "variant"]
                ):
                    score = 0.3

                rarity_scores[entity_text] = score

        return rarity_scores

    def _generate_query_modifications(
        self, query: str, entities: Dict[str, List], issues: List[QueryIssue]
    ) -> List[str]:
        """Generate basic query modification suggestions."""
        modifications = []

        if QueryIssue.TOO_SPECIFIC in issues:
            modifications.append("Try removing some specific terms")
            modifications.append("Use broader, more general terms")

        if QueryIssue.RARE_ENTITIES in issues:
            modifications.append("Replace rare terms with common synonyms")

        if QueryIssue.NO_BIOMEDICAL_ENTITIES in issues:
            modifications.append(
                "Add biological context (e.g., human, gene, disease)"
            )

        return modifications

    def _generate_broadening_suggestions(
        self, analysis: QueryAnalysis
    ) -> List[QuerySuggestion]:
        """Generate suggestions to broaden the query."""
        suggestions = []
        query = analysis.original_query

        # Remove least common entities
        words = query.split()
        if len(words) > 2:
            # Remove last word (often most specific)
            broader_query = " ".join(words[:-1])
            suggestions.append(
                QuerySuggestion(
                    suggested_query=broader_query,
                    suggestion_type=SuggestionType.QUERY_BROADENING,
                    confidence_score=0.8,
                    explanation=f"Removed '{words[-1]}' to broaden search",
                )
            )

        return suggestions

    def _generate_synonym_suggestions(
        self, analysis: QueryAnalysis
    ) -> List[QuerySuggestion]:
        """Generate suggestions using synonyms."""
        suggestions = []

        if not self.synonym_mapper:
            return suggestions

        for entity_type, entity_list in analysis.entities_found.items():
            for entity in entity_list:
                entity_text = entity.get("text", "")
                try:
                    synonyms = self.synonym_mapper.get_synonyms(
                        entity_text, entity_type
                    )
                    if synonyms:
                        # Take the first synonym as a suggestion
                        synonym = list(synonyms)[0]
                        new_query = analysis.original_query.replace(
                            entity_text, synonym
                        )

                        suggestions.append(
                            QuerySuggestion(
                                suggested_query=new_query,
                                suggestion_type=SuggestionType.SYNONYM_SUBSTITUTION,
                                confidence_score=0.7,
                                explanation=f"Replaced '{entity_text}' with '{synonym}'",
                            )
                        )
                except Exception as e:
                    logger.debug(
                        f"Synonym lookup failed for '{entity_text}': {e}"
                    )

        return suggestions

    def _generate_term_addition_suggestions(
        self, analysis: QueryAnalysis
    ) -> List[QuerySuggestion]:
        """Generate suggestions by adding relevant terms."""
        suggestions = []
        query = analysis.original_query

        # Add common biomedical context terms
        context_terms = ["human", "gene expression", "study"]

        for term in context_terms:
            if term not in query.lower():
                new_query = f"{query} {term}"
                suggestions.append(
                    QuerySuggestion(
                        suggested_query=new_query,
                        suggestion_type=SuggestionType.TERM_ADDITION,
                        confidence_score=0.6,
                        explanation=f"Added '{term}' for biological context",
                    )
                )

        return suggestions

    def _generate_spelling_suggestions(
        self, analysis: QueryAnalysis
    ) -> List[QuerySuggestion]:
        """Generate spelling correction suggestions."""
        # This would integrate with a spell checker in production
        return []

    def _generate_simplification_suggestions(
        self, analysis: QueryAnalysis
    ) -> List[QuerySuggestion]:
        """Generate suggestions to simplify complex queries."""
        suggestions = []

        if analysis.complexity_score > 0.7:
            # Extract key terms
            key_terms = self._extract_key_terms(analysis.original_query)
            if len(key_terms) > 1:
                simple_query = " ".join(key_terms[:2])  # Take top 2 terms
                suggestions.append(
                    QuerySuggestion(
                        suggested_query=simple_query,
                        suggestion_type=SuggestionType.ENTITY_SIMPLIFICATION,
                        confidence_score=0.75,
                        explanation="Simplified to focus on key terms",
                    )
                )

        return suggestions

    def _generate_structural_suggestions(
        self, analysis: QueryAnalysis
    ) -> List[QuerySuggestion]:
        """Generate suggestions for structural modifications."""
        suggestions = []

        # Convert specific terms to broader categories
        query = analysis.original_query.lower()

        # Replace specific cancer types with general "cancer"
        cancer_types = ["breast cancer", "lung cancer", "prostate cancer"]
        for cancer_type in cancer_types:
            if cancer_type in query:
                new_query = query.replace(cancer_type, "cancer")
                suggestions.append(
                    QuerySuggestion(
                        suggested_query=new_query,
                        suggestion_type=SuggestionType.STRUCTURAL_MODIFICATION,
                        confidence_score=0.6,
                        explanation=f"Generalized '{cancer_type}' to 'cancer'",
                    )
                )
                break

        return suggestions

    def _deduplicate_suggestions(
        self, suggestions: List[QuerySuggestion]
    ) -> List[QuerySuggestion]:
        """Remove duplicate suggestions."""
        seen_queries = set()
        unique_suggestions = []

        for suggestion in suggestions:
            if suggestion.suggested_query not in seen_queries:
                seen_queries.add(suggestion.suggested_query)
                unique_suggestions.append(suggestion)

        return unique_suggestions

    def _extract_key_terms(self, query: str) -> List[str]:
        """Extract key terms from a query."""
        # Simple extraction - in production use more sophisticated NLP
        words = query.lower().split()

        # Filter out common stop words and keep biomedical terms
        stop_words = {
            "the",
            "a",
            "an",
            "and",
            "or",
            "but",
            "in",
            "on",
            "at",
            "to",
            "for",
            "of",
            "with",
            "by",
        }
        key_terms = [
            word for word in words if word not in stop_words and len(word) > 2
        ]

        # Prioritize biomedical terms
        biomedical_terms = [
            term for term in key_terms if term in self.common_biomedical_terms
        ]
        other_terms = [
            term
            for term in key_terms
            if term not in self.common_biomedical_terms
        ]

        return biomedical_terms + other_terms

    def _calculate_query_similarity(self, query1: str, query2: str) -> float:
        """Calculate similarity between two queries."""
        # Simple word overlap similarity
        words1 = set(query1.lower().split())
        words2 = set(query2.lower().split())

        if not words1 or not words2:
            return 0.0

        intersection = words1.intersection(words2)
        union = words1.union(words2)

        return len(intersection) / len(union) if union else 0.0

    def _find_common_entities(self, query1: str, query2: str) -> List[str]:
        """Find common entities between two queries."""
        # Simple word-based approach - in production use proper entity matching
        words1 = set(query1.lower().split())
        words2 = set(query2.lower().split())

        common_words = words1.intersection(words2)

        # Filter for likely biomedical entities
        biomedical_common = [
            word
            for word in common_words
            if word in self.common_biomedical_terms or len(word) > 4
        ]

        return list(biomedical_common)
