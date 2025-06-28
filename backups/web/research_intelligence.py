#!/usr/bin/env python3
"""
Research Intelligence Engine - AI-powered research insights for OmicsOracle.

This module implements advanced AI algorithms for research gap identification,
cross-domain connection discovery, and methodology recommendations.
"""

import logging
import math
import random
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

logger = logging.getLogger(__name__)


class InsightType(str, Enum):
    """Types of research insights that can be generated."""

    RESEARCH_GAP = "research_gap"
    CROSS_DOMAIN_CONNECTION = "cross_domain_connection"
    METHODOLOGY_RECOMMENDATION = "methodology_recommendation"
    TREND_ANALYSIS = "trend_analysis"
    COLLABORATION_OPPORTUNITY = "collaboration_opportunity"


class ConfidenceLevel(str, Enum):
    """Confidence levels for AI-generated insights."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class ResearchEntity:
    """Represents a research entity (disease, tissue, technique, etc.)."""

    name: str
    category: str
    frequency: int = 0
    recent_activity: float = 0.0
    associated_terms: List[str] = field(default_factory=list)
    publications_count: int = 0
    datasets_count: int = 0


@dataclass
class ResearchInsight:
    """Represents an AI-generated research insight."""

    insight_type: InsightType
    title: str
    description: str
    confidence: ConfidenceLevel
    entities: List[str]
    supporting_evidence: Dict[str, Any]
    actionable_suggestions: List[str]
    potential_impact: str
    research_domains: List[str]
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class CrossDomainConnection:
    """Represents a connection between different research domains."""

    domain_a: str
    domain_b: str
    connection_strength: float
    shared_entities: List[str]
    potential_insights: List[str]
    supporting_studies: List[str]
    novelty_score: float


@dataclass
class MethodologyRecommendation:
    """Represents a recommended research methodology."""

    technique: str
    confidence: float
    rationale: str
    success_examples: List[str]
    required_resources: List[str]
    expected_outcomes: List[str]
    alternative_approaches: List[str]


class ResearchIntelligenceEngine:
    """Core AI engine for generating research insights."""

    def __init__(self):
        """Initialize the research intelligence engine."""
        self.entity_knowledge_base: Dict[str, ResearchEntity] = {}
        self.research_trends: Dict[str, List[float]] = {}
        self.domain_connections: Dict[str, Dict[str, float]] = defaultdict(dict)
        self.methodology_success_rates: Dict[str, Dict[str, float]] = defaultdict(dict)
        self.vectorizer = TfidfVectorizer(max_features=1000, stop_words="english")
        self.entity_vectors: Optional[np.ndarray] = None

        # Initialize with sample knowledge base
        self._initialize_knowledge_base()

    def _initialize_knowledge_base(self):
        """Initialize the research knowledge base with sample data."""
        # Sample entities across different categories
        diseases = [
            "cancer",
            "alzheimer",
            "diabetes",
            "cardiovascular disease",
            "parkinson",
            "huntington",
            "multiple sclerosis",
            "crohn disease",
            "rheumatoid arthritis",
            "lupus",
            "autism",
            "schizophrenia",
        ]

        tissues = [
            "brain",
            "heart",
            "liver",
            "kidney",
            "lung",
            "muscle",
            "bone",
            "skin",
            "blood",
            "pancreas",
            "intestine",
            "spleen",
        ]

        techniques = [
            "RNA-seq",
            "scRNA-seq",
            "WGBS",
            "RRBS",
            "ChIP-seq",
            "ATAC-seq",
            "Hi-C",
            "proteomics",
            "metabolomics",
            "GWAS",
            "WES",
            "WGS",
        ]

        organisms = [
            "Homo sapiens",
            "Mus musculus",
            "Rattus norvegicus",
            "Drosophila melanogaster",
            "Caenorhabditis elegans",
            "Danio rerio",
        ]

        # Create research entities with simulated metadata
        for disease in diseases:
            self.entity_knowledge_base[disease] = ResearchEntity(
                name=disease,
                category="disease",
                frequency=random.randint(100, 5000),
                recent_activity=random.uniform(0.1, 1.0),
                publications_count=random.randint(500, 10000),
                datasets_count=random.randint(50, 1000),
            )

        for tissue in tissues:
            self.entity_knowledge_base[tissue] = ResearchEntity(
                name=tissue,
                category="tissue",
                frequency=random.randint(200, 3000),
                recent_activity=random.uniform(0.2, 0.9),
                publications_count=random.randint(300, 7000),
                datasets_count=random.randint(30, 800),
            )

        for technique in techniques:
            self.entity_knowledge_base[technique] = ResearchEntity(
                name=technique,
                category="technique",
                frequency=random.randint(50, 2000),
                recent_activity=random.uniform(0.3, 1.0),
                publications_count=random.randint(100, 5000),
                datasets_count=random.randint(20, 600),
            )

        for organism in organisms:
            self.entity_knowledge_base[organism] = ResearchEntity(
                name=organism,
                category="organism",
                frequency=random.randint(500, 8000),
                recent_activity=random.uniform(0.4, 1.0),
                publications_count=random.randint(1000, 15000),
                datasets_count=random.randint(100, 2000),
            )

    async def identify_research_gaps(
        self, research_context: List[str], min_confidence: float = 0.6
    ) -> List[ResearchInsight]:
        """Identify potential research gaps using AI analysis."""
        logger.info(f"Identifying research gaps for context: {research_context}")

        gaps = []

        # Analyze entity frequency vs recent activity
        underexplored_entities = self._find_underexplored_entities()

        # Generate gap insights
        for entity_name, gap_score in underexplored_entities[:5]:
            entity = self.entity_knowledge_base[entity_name]

            # Calculate confidence based on data availability and gap score
            confidence = self._calculate_gap_confidence(entity, gap_score)

            if confidence >= min_confidence:
                gap = ResearchInsight(
                    insight_type=InsightType.RESEARCH_GAP,
                    title=f"Underexplored Research Area: {entity.name.title()}",
                    description=(
                        f"Analysis suggests {entity.name} in {entity.category} research "
                        f"shows significant potential but limited recent activity. "
                        f"Gap score: {gap_score:.2f}"
                    ),
                    confidence=self._score_to_confidence_level(confidence),
                    entities=[entity.name],
                    supporting_evidence={
                        "gap_score": gap_score,
                        "publications_count": entity.publications_count,
                        "datasets_count": entity.datasets_count,
                        "recent_activity": entity.recent_activity,
                        "category": entity.category,
                    },
                    actionable_suggestions=[
                        f"Consider investigating {entity.name} using modern techniques",
                        f"Look for datasets combining {entity.name} with emerging methodologies",
                        f"Explore cross-species studies involving {entity.name}",
                        f"Investigate {entity.name} in the context of precision medicine",
                    ],
                    potential_impact="High - addressing understudied area with good foundational data",
                    research_domains=[entity.category],
                )
                gaps.append(gap)

        # Find technique-disease gaps
        technique_gaps = await self._identify_technique_disease_gaps(research_context)
        gaps.extend(technique_gaps)

        return sorted(
            gaps,
            key=lambda x: self._confidence_to_score(x.confidence),
            reverse=True,
        )

    def _find_underexplored_entities(self) -> List[Tuple[str, float]]:
        """Find entities with high potential but low recent activity."""
        gap_scores = []

        for name, entity in self.entity_knowledge_base.items():
            # Gap score combines low recent activity with high foundational interest
            foundational_score = (
                math.log(entity.publications_count + 1) * 0.3 + math.log(entity.datasets_count + 1) * 0.7
            )

            # Inverse relationship with recent activity (lower activity = higher gap)
            activity_gap = 1.0 - entity.recent_activity

            gap_score = foundational_score * activity_gap
            gap_scores.append((name, gap_score))

        return sorted(gap_scores, key=lambda x: x[1], reverse=True)

    async def _identify_technique_disease_gaps(self, context: List[str]) -> List[ResearchInsight]:
        """Identify gaps where certain techniques haven't been applied to diseases."""
        gaps = []

        diseases = [e for e in self.entity_knowledge_base.values() if e.category == "disease"]
        techniques = [e for e in self.entity_knowledge_base.values() if e.category == "technique"]

        # Find underexplored technique-disease combinations
        for disease in diseases[:3]:  # Limit for performance
            for technique in techniques[:3]:
                # Simulate gap analysis (in real implementation, would query actual data)
                combination_score = random.uniform(0.3, 0.9)

                if combination_score > 0.7:  # High potential combination
                    gap = ResearchInsight(
                        insight_type=InsightType.RESEARCH_GAP,
                        title=f"Unexplored Application: {technique.name} in {disease.name}",
                        description=(
                            f"Limited research has applied {technique.name} to study "
                            f"{disease.name}. This combination shows high potential "
                            f"for novel discoveries."
                        ),
                        confidence=ConfidenceLevel.MEDIUM,
                        entities=[disease.name, technique.name],
                        supporting_evidence={
                            "combination_score": combination_score,
                            "disease_activity": disease.recent_activity,
                            "technique_activity": technique.recent_activity,
                        },
                        actionable_suggestions=[
                            f"Design {technique.name} experiments focused on {disease.name}",
                            f"Search for pilot studies combining {technique.name} and {disease.name}",
                            "Consider collaborative projects bridging these research areas",
                        ],
                        potential_impact="Medium to High - novel methodological application",
                        research_domains=["disease", "technique"],
                    )
                    gaps.append(gap)

        return gaps[:3]  # Return top 3 technique-disease gaps

    async def discover_cross_domain_connections(
        self, domains: List[str], min_strength: float = 0.5
    ) -> List[CrossDomainConnection]:
        """Discover connections between different research domains."""
        logger.info(f"Discovering cross-domain connections for: {domains}")

        connections = []

        # Analyze entity co-occurrence patterns
        domain_entities = defaultdict(list)
        for entity in self.entity_knowledge_base.values():
            domain_entities[entity.category].append(entity)

        # Find cross-domain entity relationships
        domain_pairs = [(d1, d2) for i, d1 in enumerate(domains) for d2 in domains[i + 1 :]]

        for domain_a, domain_b in domain_pairs:
            connection = await self._analyze_domain_connection(domain_a, domain_b, domain_entities)

            if connection and connection.connection_strength >= min_strength:
                connections.append(connection)

        return sorted(connections, key=lambda x: x.connection_strength, reverse=True)

    async def _analyze_domain_connection(
        self,
        domain_a: str,
        domain_b: str,
        domain_entities: Dict[str, List[ResearchEntity]],
    ) -> Optional[CrossDomainConnection]:
        """Analyze the connection strength between two research domains."""
        entities_a = domain_entities.get(domain_a, [])
        entities_b = domain_entities.get(domain_b, [])

        if not entities_a or not entities_b:
            return None

        # Calculate connection strength based on entity interactions
        shared_entities = []
        connection_scores = []

        for entity_a in entities_a[:5]:  # Limit for performance
            for entity_b in entities_b[:5]:
                # Simulate connection analysis (would use real co-occurrence data)
                connection_score = self._calculate_entity_connection(entity_a, entity_b)

                if connection_score > 0.3:
                    connection_scores.append(connection_score)
                    shared_entities.extend([entity_a.name, entity_b.name])

        if not connection_scores:
            return None

        avg_strength = np.mean(connection_scores)
        novelty_score = 1.0 - (avg_strength * 0.5)  # Higher novelty for weaker existing connections

        return CrossDomainConnection(
            domain_a=domain_a,
            domain_b=domain_b,
            connection_strength=avg_strength,
            shared_entities=list(set(shared_entities)),
            potential_insights=[
                f"Explore {domain_a}-{domain_b} interactions in disease contexts",
                f"Investigate shared pathways between {domain_a} and {domain_b}",
                f"Consider multi-omics approaches bridging {domain_a} and {domain_b}",
            ],
            supporting_studies=[
                f"Pilot study: {domain_a} influences on {domain_b}",
                f"Comparative analysis: {domain_a} vs {domain_b} in disease models",
            ],
            novelty_score=novelty_score,
        )

    def _calculate_entity_connection(self, entity_a: ResearchEntity, entity_b: ResearchEntity) -> float:
        """Calculate connection strength between two entities."""
        # Simulate connection calculation (would use real co-occurrence data)
        category_bonus = 0.2 if entity_a.category != entity_b.category else 0.0
        activity_correlation = min(entity_a.recent_activity, entity_b.recent_activity)
        frequency_correlation = min(entity_a.frequency, entity_b.frequency) / max(
            entity_a.frequency, entity_b.frequency
        )

        return (activity_correlation * 0.4 + frequency_correlation * 0.4 + category_bonus) * random.uniform(
            0.7, 1.3
        )

    async def recommend_methodologies(
        self, research_goals: List[str], constraints: Dict[str, Any] = None
    ) -> List[MethodologyRecommendation]:
        """Recommend research methodologies based on goals and constraints."""
        logger.info(f"Recommending methodologies for goals: {research_goals}")

        constraints = constraints or {}
        recommendations = []

        # Analyze goals to determine suitable techniques
        goal_keywords = " ".join(research_goals).lower()

        technique_entities = [e for e in self.entity_knowledge_base.values() if e.category == "technique"]

        for technique in technique_entities:
            relevance_score = self._calculate_technique_relevance(technique, goal_keywords)

            if relevance_score > 0.4:
                recommendation = MethodologyRecommendation(
                    technique=technique.name,
                    confidence=relevance_score,
                    rationale=(
                        f"{technique.name} is well-suited for your research goals due to "
                        f"its effectiveness in similar studies (relevance: {relevance_score:.2f})"
                    ),
                    success_examples=[
                        f"Study A: Used {technique.name} to investigate similar research questions",
                        f"Study B: {technique.name} provided key insights in related domain",
                    ],
                    required_resources=[
                        f"Specialized equipment for {technique.name}",
                        f"Bioinformatics expertise for {technique.name} data analysis",
                        "Sample preparation protocols",
                    ],
                    expected_outcomes=[
                        f"High-resolution data from {technique.name}",
                        f"Novel insights into research questions using {technique.name}",
                        "Publication-ready results",
                    ],
                    alternative_approaches=[
                        f"Alternative to {technique.name}: consider complementary techniques",
                        "Multi-omics approach combining multiple methodologies",
                    ],
                )
                recommendations.append(recommendation)

        return sorted(recommendations, key=lambda x: x.confidence, reverse=True)[:5]

    def _calculate_technique_relevance(self, technique: ResearchEntity, goal_keywords: str) -> float:
        """Calculate how relevant a technique is to research goals."""
        # Simulate relevance calculation based on technique characteristics
        base_relevance = technique.recent_activity * 0.6 + (technique.frequency / 5000) * 0.4

        # Add keyword matching bonus (simplified)
        keyword_bonus = 0.0
        if any(keyword in technique.name.lower() for keyword in goal_keywords.split()):
            keyword_bonus = 0.3

        return min(base_relevance + keyword_bonus, 1.0)

    def _calculate_gap_confidence(self, entity: ResearchEntity, gap_score: float) -> float:
        """Calculate confidence level for a research gap."""
        data_quality = (
            min(entity.publications_count / 1000, 1.0) * 0.4 + min(entity.datasets_count / 100, 1.0) * 0.6
        )

        return (gap_score * 0.6 + data_quality * 0.4) / 2

    def _score_to_confidence_level(self, score: float) -> ConfidenceLevel:
        """Convert numeric confidence score to confidence level."""
        if score >= 0.7:
            return ConfidenceLevel.HIGH
        elif score >= 0.5:
            return ConfidenceLevel.MEDIUM
        else:
            return ConfidenceLevel.LOW

    def _confidence_to_score(self, confidence: ConfidenceLevel) -> float:
        """Convert confidence level to numeric score for sorting."""
        mapping = {
            ConfidenceLevel.HIGH: 0.8,
            ConfidenceLevel.MEDIUM: 0.6,
            ConfidenceLevel.LOW: 0.4,
        }
        return mapping.get(confidence, 0.0)


class PersonalizationEngine:
    """Engine for personalizing research recommendations."""

    def __init__(self):
        """Initialize the personalization engine."""
        self.user_profiles: Dict[str, Dict[str, Any]] = {}
        self.interaction_history: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    def update_user_profile(self, user_id: str, interaction: Dict[str, Any]):
        """Update user profile based on interactions."""
        if user_id not in self.user_profiles:
            self.user_profiles[user_id] = {
                "preferred_domains": Counter(),
                "preferred_techniques": Counter(),
                "research_interests": set(),
                "activity_patterns": [],
                "last_updated": datetime.now(),
            }

        profile = self.user_profiles[user_id]

        # Update preferences based on interaction
        if "domain" in interaction:
            profile["preferred_domains"][interaction["domain"]] += 1

        if "entities" in interaction:
            for entity in interaction["entities"]:
                profile["research_interests"].add(entity)

        self.interaction_history[user_id].append({**interaction, "timestamp": datetime.now()})

        profile["last_updated"] = datetime.now()

    def get_personalized_recommendations(
        self, user_id: str, base_insights: List[ResearchInsight]
    ) -> List[ResearchInsight]:
        """Personalize research insights based on user profile."""
        if user_id not in self.user_profiles:
            return base_insights

        profile = self.user_profiles[user_id]

        # Score insights based on user preferences
        scored_insights = []
        for insight in base_insights:
            relevance_score = self._calculate_insight_relevance(insight, profile)
            scored_insights.append((insight, relevance_score))

        # Sort by relevance and return
        scored_insights.sort(key=lambda x: x[1], reverse=True)
        return [insight for insight, score in scored_insights]

    def _calculate_insight_relevance(self, insight: ResearchInsight, profile: Dict[str, Any]) -> float:
        """Calculate how relevant an insight is to a user's profile."""
        relevance = 0.0

        # Domain preference matching
        for domain in insight.research_domains:
            if domain in profile["preferred_domains"]:
                relevance += profile["preferred_domains"][domain] * 0.3

        # Entity interest matching
        entity_matches = len(set(insight.entities) & profile["research_interests"])
        relevance += entity_matches * 0.5

        # Confidence bonus
        confidence_bonus = {
            ConfidenceLevel.HIGH: 0.3,
            ConfidenceLevel.MEDIUM: 0.2,
            ConfidenceLevel.LOW: 0.1,
        }
        relevance += confidence_bonus.get(insight.confidence, 0.0)

        return min(relevance, 1.0)


# Global instances
research_intelligence = ResearchIntelligenceEngine()
personalization_engine = PersonalizationEngine()
