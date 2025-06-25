#!/usr/bin/env python3
"""
Advanced Research Dashboard Widgets - Phase 2 Intelligence Layer.

This module implements AI-powered advanced widgets including Discovery Assistant,
Comparative Analysis Panel, and intelligent recommendation systems.
"""

import logging
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter

from .research_dashboard import ResearchContext, ResearchDomain
from .research_intelligence import (
    ConfidenceLevel,
    CrossDomainConnection,
    InsightType,
    MethodologyRecommendation,
    ResearchInsight,
    personalization_engine,
    research_intelligence,
)

logger = logging.getLogger(__name__)


@dataclass
class DiscoveryAssistantData:
    """Data structure for Discovery Assistant widget."""

    research_gaps: List[Dict[str, Any]]
    cross_domain_connections: List[Dict[str, Any]]
    methodology_recommendations: List[Dict[str, Any]]
    personalized_insights: List[Dict[str, Any]]
    ai_confidence_score: float
    discovery_opportunities: int


@dataclass
class ComparativeAnalysisData:
    """Data structure for Comparative Analysis widget."""

    comparison_matrix: List[List[Any]]
    similarity_scores: Dict[str, float]
    key_differences: List[str]
    recommendations: List[str]
    statistical_significance: Dict[str, float]


class DiscoveryAssistantWidget:
    """AI-powered research discovery assistant widget."""

    def __init__(self):
        """Initialize the discovery assistant widget."""
        self.name = "discovery_assistant"
        self.title = "🔍 AI Discovery Assistant"
        self.description = "AI-powered research discovery and recommendations"

    async def get_data(self, context: ResearchContext) -> Dict[str, Any]:
        """Generate discovery assistant data with AI insights."""
        logger.info(
            f"Generating discovery assistant data for context: {context.user_id}"
        )

        # Generate research gaps
        research_gaps = await research_intelligence.identify_research_gaps(
            research_context=context.research_domains, min_confidence=0.5
        )

        # Discover cross-domain connections
        cross_domain_connections = (
            await research_intelligence.discover_cross_domain_connections(
                domains=["disease", "tissue", "technique", "organism"],
                min_strength=0.4,
            )
        )

        # Get methodology recommendations
        research_goals = [
            f"Study {domain}" for domain in context.research_domains
        ]
        methodology_recommendations = (
            await research_intelligence.recommend_methodologies(
                research_goals=research_goals, constraints={}
            )
        )

        # Personalize insights
        all_insights = research_gaps[:10]  # Limit for performance
        personalized_insights = (
            personalization_engine.get_personalized_recommendations(
                user_id=context.user_id, base_insights=all_insights
            )
        )

        # Calculate overall AI confidence
        confidence_scores = [
            self._insight_to_confidence_score(insight)
            for insight in research_gaps[:5]
        ]
        ai_confidence_score = (
            sum(confidence_scores) / len(confidence_scores)
            if confidence_scores
            else 0.0
        )

        # Count discovery opportunities
        discovery_opportunities = (
            len(research_gaps)
            + len(cross_domain_connections)
            + len(methodology_recommendations)
        )

        assistant_data = DiscoveryAssistantData(
            research_gaps=[
                self._insight_to_dict(gap) for gap in research_gaps[:5]
            ],
            cross_domain_connections=[
                self._connection_to_dict(conn)
                for conn in cross_domain_connections[:3]
            ],
            methodology_recommendations=[
                self._recommendation_to_dict(rec)
                for rec in methodology_recommendations[:3]
            ],
            personalized_insights=[
                self._insight_to_dict(insight)
                for insight in personalized_insights[:5]
            ],
            ai_confidence_score=ai_confidence_score,
            discovery_opportunities=discovery_opportunities,
        )

        return {
            "success": True,
            "widget_type": self.name,
            "data": asdict(assistant_data),
            "config": {
                "type": "discovery_assistant",
                "layout": "tabbed",
                "sections": [
                    {
                        "id": "research_gaps",
                        "title": "Research Gaps",
                        "icon": "🎯",
                    },
                    {
                        "id": "cross_domain",
                        "title": "Cross-Domain Connections",
                        "icon": "🔗",
                    },
                    {
                        "id": "methodologies",
                        "title": "Methodology Recommendations",
                        "icon": "🧪",
                    },
                    {
                        "id": "personalized",
                        "title": "Personalized Insights",
                        "icon": "⭐",
                    },
                ],
                "ai_features": {
                    "confidence_display": True,
                    "interactive_exploration": True,
                    "export_insights": True,
                },
            },
            "metadata": {
                "widget_type": self.name,
                "last_updated": datetime.now().isoformat(),
                "cache_duration": 600.0,  # 10 minutes
                "ai_processing_time": "< 2 seconds",
            },
        }

    def _insight_to_dict(self, insight: ResearchInsight) -> Dict[str, Any]:
        """Convert ResearchInsight to dictionary."""
        return {
            "type": insight.insight_type.value,
            "title": insight.title,
            "description": insight.description,
            "confidence": insight.confidence.value,
            "entities": insight.entities,
            "supporting_evidence": insight.supporting_evidence,
            "actionable_suggestions": insight.actionable_suggestions,
            "potential_impact": insight.potential_impact,
            "research_domains": insight.research_domains,
            "created_at": insight.created_at.isoformat(),
        }

    def _connection_to_dict(
        self, connection: CrossDomainConnection
    ) -> Dict[str, Any]:
        """Convert CrossDomainConnection to dictionary."""
        return {
            "domain_a": connection.domain_a,
            "domain_b": connection.domain_b,
            "connection_strength": connection.connection_strength,
            "shared_entities": connection.shared_entities,
            "potential_insights": connection.potential_insights,
            "supporting_studies": connection.supporting_studies,
            "novelty_score": connection.novelty_score,
        }

    def _recommendation_to_dict(
        self, recommendation: MethodologyRecommendation
    ) -> Dict[str, Any]:
        """Convert MethodologyRecommendation to dictionary."""
        return {
            "technique": recommendation.technique,
            "confidence": recommendation.confidence,
            "rationale": recommendation.rationale,
            "success_examples": recommendation.success_examples,
            "required_resources": recommendation.required_resources,
            "expected_outcomes": recommendation.expected_outcomes,
            "alternative_approaches": recommendation.alternative_approaches,
        }

    def _insight_to_confidence_score(self, insight: ResearchInsight) -> float:
        """Convert insight confidence to numeric score."""
        mapping = {
            ConfidenceLevel.HIGH: 0.8,
            ConfidenceLevel.MEDIUM: 0.6,
            ConfidenceLevel.LOW: 0.4,
        }
        return mapping.get(insight.confidence, 0.0)


class ComparativeAnalysisWidget:
    """Advanced comparative analysis widget for research data."""

    def __init__(self):
        """Initialize the comparative analysis widget."""
        self.name = "comparative_analysis"
        self.title = "📊 Comparative Analysis Panel"
        self.description = "Side-by-side comparison of datasets, studies, and research approaches"

    async def get_data(
        self, context: ResearchContext, comparison_items: List[str] = None
    ) -> Dict[str, Any]:
        """Generate comparative analysis data."""
        logger.info(f"Generating comparative analysis for: {comparison_items}")

        comparison_items = comparison_items or [
            "RNA-seq",
            "scRNA-seq",
            "ATAC-seq",
        ]

        # Generate comparison matrix
        comparison_matrix = []
        criteria = [
            "Data Resolution",
            "Cost Effectiveness",
            "Technical Complexity",
            "Analysis Requirements",
            "Publication Impact",
        ]

        for item in comparison_items:
            row = [item]
            # Simulate comparison scores (would use real data in production)
            for criterion in criteria:
                score = self._calculate_comparison_score(item, criterion)
                row.append(score)
            comparison_matrix.append(row)

        # Calculate similarity scores
        similarity_scores = {}
        for i, item_a in enumerate(comparison_items):
            for j, item_b in enumerate(comparison_items[i + 1 :], i + 1):
                similarity = self._calculate_similarity(item_a, item_b)
                similarity_scores[f"{item_a} vs {item_b}"] = similarity

        # Generate key differences
        key_differences = [
            f"{comparison_items[0]} excels in data resolution but requires more computational resources",
            f"{comparison_items[1]} offers cellular resolution but at higher cost",
            f"{comparison_items[2]} provides accessibility insights but limited to open chromatin",
        ]

        # Generate recommendations
        recommendations = [
            f"For single-cell studies, prioritize {comparison_items[1]}",
            f"For cost-effective bulk analysis, consider {comparison_items[0]}",
            f"For chromatin accessibility, {comparison_items[2]} is most appropriate",
        ]

        # Calculate statistical significance (simulated)
        statistical_significance = {
            "p_value": 0.001,
            "effect_size": 0.75,
            "confidence_interval": [0.65, 0.85],
        }

        analysis_data = ComparativeAnalysisData(
            comparison_matrix=comparison_matrix,
            similarity_scores=similarity_scores,
            key_differences=key_differences,
            recommendations=recommendations,
            statistical_significance=statistical_significance,
        )

        return {
            "success": True,
            "widget_type": self.name,
            "data": asdict(analysis_data),
            "config": {
                "type": "comparative_table",
                "layout": "split_view",
                "features": {
                    "sortable_columns": True,
                    "exportable": True,
                    "interactive_filtering": True,
                    "statistical_overlay": True,
                },
                "visualization": {
                    "chart_types": ["radar", "heatmap", "scatter"],
                    "color_scheme": "comparative_blues",
                },
            },
            "metadata": {
                "widget_type": self.name,
                "last_updated": datetime.now().isoformat(),
                "cache_duration": 300.0,
                "comparison_items": comparison_items,
            },
        }

    def _calculate_comparison_score(self, item: str, criterion: str) -> float:
        """Calculate comparison score for item-criterion pair."""
        # Simulate scoring based on known characteristics
        base_scores = {
            "RNA-seq": {
                "Data Resolution": 0.8,
                "Cost Effectiveness": 0.9,
                "Technical Complexity": 0.6,
            },
            "scRNA-seq": {
                "Data Resolution": 0.95,
                "Cost Effectiveness": 0.4,
                "Technical Complexity": 0.3,
            },
            "ATAC-seq": {
                "Data Resolution": 0.7,
                "Cost Effectiveness": 0.7,
                "Technical Complexity": 0.7,
            },
        }

        return base_scores.get(item, {}).get(criterion, 0.5)

    def _calculate_similarity(self, item_a: str, item_b: str) -> float:
        """Calculate similarity between two items."""
        # Simulate similarity calculation
        similarity_matrix = {
            ("RNA-seq", "scRNA-seq"): 0.7,
            ("RNA-seq", "ATAC-seq"): 0.4,
            ("scRNA-seq", "ATAC-seq"): 0.3,
        }

        key = tuple(sorted([item_a, item_b]))
        return similarity_matrix.get(key, 0.0)


class ResearchProjectManagerWidget:
    """Research project management and tracking widget."""

    def __init__(self):
        """Initialize the research project manager widget."""
        self.name = "research_project_manager"
        self.title = "📋 Research Project Manager"
        self.description = (
            "Track and manage ongoing research interests and projects"
        )

    async def get_data(self, context: ResearchContext) -> Dict[str, Any]:
        """Generate research project management data."""
        logger.info(
            f"Generating project management data for user: {context.user_id}"
        )

        # Simulate user's saved research queries and projects
        saved_queries = [
            {
                "id": "query_001",
                "title": "Cancer RNA-seq Studies",
                "query": "cancer AND RNA-seq AND human",
                "created_date": "2025-06-20",
                "last_accessed": "2025-06-23",
                "result_count": 1247,
                "status": "active",
            },
            {
                "id": "query_002",
                "title": "Brain ATAC-seq Analysis",
                "query": "brain AND ATAC-seq AND mouse",
                "created_date": "2025-06-18",
                "last_accessed": "2025-06-22",
                "result_count": 389,
                "status": "monitoring",
            },
        ]

        # Research domain monitoring alerts
        domain_alerts = [
            {
                "domain": "cancer",
                "new_datasets": 15,
                "alert_type": "high_activity",
                "message": "15 new cancer-related datasets added this week",
            },
            {
                "domain": "single-cell",
                "new_datasets": 8,
                "alert_type": "medium_activity",
                "message": "Growing activity in single-cell genomics",
            },
        ]

        # Export and download history
        export_history = [
            {
                "export_id": "exp_001",
                "dataset": "GSE123456",
                "export_date": "2025-06-22",
                "format": "CSV",
                "size": "2.3 GB",
                "status": "completed",
            },
            {
                "export_id": "exp_002",
                "dataset": "GSE789012",
                "export_date": "2025-06-21",
                "format": "JSON",
                "size": "856 MB",
                "status": "completed",
            },
        ]

        # Research collaboration opportunities
        collaboration_opportunities = [
            {
                "opportunity_id": "collab_001",
                "title": "Multi-omics Cancer Analysis",
                "description": "Looking for partners in cancer genomics research",
                "matching_score": 0.85,
                "research_domains": ["cancer", "genomics", "multi-omics"],
            }
        ]

        return {
            "success": True,
            "widget_type": self.name,
            "data": {
                "saved_queries": saved_queries,
                "domain_alerts": domain_alerts,
                "export_history": export_history,
                "collaboration_opportunities": collaboration_opportunities,
                "project_stats": {
                    "total_queries": len(saved_queries),
                    "active_monitoring": len(
                        [
                            q
                            for q in saved_queries
                            if q["status"] == "monitoring"
                        ]
                    ),
                    "total_exports": len(export_history),
                    "collaboration_matches": len(collaboration_opportunities),
                },
            },
            "config": {
                "type": "project_manager",
                "layout": "dashboard",
                "sections": [
                    {"id": "queries", "title": "Saved Queries", "icon": "🔍"},
                    {
                        "id": "monitoring",
                        "title": "Domain Monitoring",
                        "icon": "📊",
                    },
                    {"id": "exports", "title": "Export History", "icon": "📥"},
                    {
                        "id": "collaboration",
                        "title": "Collaboration",
                        "icon": "🤝",
                    },
                ],
                "features": {
                    "query_management": True,
                    "alert_system": True,
                    "export_tracking": True,
                    "collaboration_matching": True,
                },
            },
            "metadata": {
                "widget_type": self.name,
                "last_updated": datetime.now().isoformat(),
                "cache_duration": 180.0,  # 3 minutes
                "user_id": context.user_id,
            },
        }


# Initialize advanced widgets
discovery_assistant = DiscoveryAssistantWidget()
comparative_analysis = ComparativeAnalysisWidget()
research_project_manager = ResearchProjectManagerWidget()

# Advanced widgets router
advanced_router = APIRouter(
    prefix="/api/research/advanced", tags=["advanced-widgets"]
)


@advanced_router.get("/widgets/discovery_assistant")
async def get_discovery_assistant_data(
    user_id: str = "anonymous", domain: str = "general_genomics"
):
    """Get AI-powered discovery assistant data."""
    context = ResearchContext(user_id=user_id, research_domains=[domain])

    return await discovery_assistant.get_data(context)


@advanced_router.get("/widgets/comparative_analysis")
async def get_comparative_analysis_data(
    user_id: str = "anonymous", comparison_items: str = None
):
    """Get comparative analysis data."""
    context = ResearchContext(user_id=user_id)

    items = comparison_items.split(",") if comparison_items else None
    return await comparative_analysis.get_data(context, items)


@advanced_router.get("/widgets/research_project_manager")
async def get_research_project_manager_data(user_id: str = "anonymous"):
    """Get research project management data."""
    context = ResearchContext(user_id=user_id)

    return await research_project_manager.get_data(context)


@advanced_router.post("/personalization/update")
async def update_user_personalization(
    user_id: str, interaction_data: Dict[str, Any]
):
    """Update user personalization based on interactions."""
    personalization_engine.update_user_profile(user_id, interaction_data)

    return {
        "success": True,
        "message": "User profile updated successfully",
        "user_id": user_id,
        "timestamp": datetime.now().isoformat(),
    }
