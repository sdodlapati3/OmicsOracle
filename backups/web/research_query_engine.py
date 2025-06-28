#!/usr/bin/env python3
"""
Interactive Research Query Engine - Natural language interface for research insights.

This module enables researchers to ask questions in natural language and receive
comprehensive research insights, data summaries, and actionable recommendations.
"""

import logging
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from .research_intelligence import ResearchContext, personalization_engine, research_intelligence

logger = logging.getLogger(__name__)


class ResearchQuery(BaseModel):
    """Model for research queries."""

    query: str
    user_id: str = "anonymous"
    context: Optional[Dict[str, Any]] = None
    response_format: str = "comprehensive"  # comprehensive, summary, bullet_points


@dataclass
class QueryResponse:
    """Response structure for research queries."""

    query: str
    answer: str
    insights: List[Dict[str, Any]]
    data_sources: List[str]
    confidence_score: float
    follow_up_suggestions: List[str]
    export_options: List[str]
    timestamp: datetime


class ResearchQueryEngine:
    """Natural language query engine for research insights."""

    def __init__(self):
        """Initialize the query engine."""
        self.query_patterns = {
            "research_gaps": [
                r"what.*gaps?.*research",
                r"underexplored.*areas?",
                r"research.*opportunities",
                r"what.*should.*study",
                r"unexplored.*topics",
            ],
            "methodology": [
                r"what.*method.*should.*use",
                r"best.*technique.*for",
                r"how.*to.*study",
                r"recommend.*approach",
                r"which.*sequencing",
            ],
            "comparisons": [
                r"compare.*between",
                r"difference.*between",
                r"vs\.?|versus",
                r"better.*than",
                r"advantage.*of",
            ],
            "trends": [
                r"trend.*in",
                r"popular.*research",
                r"emerging.*field",
                r"recent.*development",
                r"what.*happening.*in",
            ],
            "data_summary": [
                r"summarize.*data",
                r"overview.*of",
                r"tell.*me.*about",
                r"information.*on",
                r"what.*is.*known.*about",
            ],
        }

    async def process_query(self, query: ResearchQuery) -> QueryResponse:
        """Process a natural language research query."""
        logger.info(f"Processing query: {query.query}")

        # Analyze query intent
        query_type = self._classify_query(query.query)
        entities = self._extract_entities(query.query)

        # Generate response based on query type
        if query_type == "research_gaps":
            response = await self._handle_research_gaps_query(query, entities)
        elif query_type == "methodology":
            response = await self._handle_methodology_query(query, entities)
        elif query_type == "comparisons":
            response = await self._handle_comparison_query(query, entities)
        elif query_type == "trends":
            response = await self._handle_trends_query(query, entities)
        elif query_type == "data_summary":
            response = await self._handle_data_summary_query(query, entities)
        else:
            response = await self._handle_general_query(query, entities)

        # Personalize response
        if query.user_id != "anonymous":
            response = await self._personalize_response(response, query.user_id)

        return response

    def _classify_query(self, query: str) -> str:
        """Classify the type of research query."""
        query_lower = query.lower()

        for query_type, patterns in self.query_patterns.items():
            for pattern in patterns:
                if re.search(pattern, query_lower):
                    return query_type

        return "general"

    def _extract_entities(self, query: str) -> List[str]:
        """Extract research entities from the query."""
        # Simple entity extraction (would use NLP in production)
        entities = []

        # Common research entities
        research_terms = [
            "cancer",
            "alzheimer",
            "diabetes",
            "brain",
            "heart",
            "liver",
            "rna-seq",
            "scrna-seq",
            "atac-seq",
            "chip-seq",
            "wgbs",
            "human",
            "mouse",
            "rat",
            "genomics",
            "proteomics",
        ]

        query_lower = query.lower()
        for term in research_terms:
            if term in query_lower:
                entities.append(term)

        return entities

    async def _handle_research_gaps_query(self, query: ResearchQuery, entities: List[str]) -> QueryResponse:
        """Handle research gaps queries."""
        context = ResearchContext(
            user_id=query.user_id,
            research_domains=entities if entities else ["general_genomics"],
        )

        # Get research gaps
        gaps = await research_intelligence.identify_research_gaps(
            research_context=context.research_domains, min_confidence=0.5
        )

        # Format response
        answer = "Based on AI analysis, here are the key research gaps I've identified:\n\n"

        for i, gap in enumerate(gaps[:3], 1):
            answer += f"{i}. **{gap.title}**\n"
            answer += f"   - {gap.description}\n"
            answer += f"   - Confidence: {gap.confidence.value}\n"
            answer += f"   - Potential Impact: {gap.potential_impact}\n\n"

        answer += "These gaps represent opportunities for novel research with significant potential impact."

        insights = [
            {
                "type": "research_gap",
                "title": gap.title,
                "description": gap.description,
                "confidence": gap.confidence.value,
                "actionable_suggestions": gap.actionable_suggestions,
            }
            for gap in gaps[:5]
        ]

        return QueryResponse(
            query=query.query,
            answer=answer,
            insights=insights,
            data_sources=[
                "AI Research Intelligence Engine",
                "Entity Knowledge Base",
            ],
            confidence_score=0.85,
            follow_up_suggestions=[
                "Ask about specific methodology recommendations for these gaps",
                "Compare different approaches to address these research areas",
                "Get cross-domain connection insights for these topics",
            ],
            export_options=[
                "Research Gap Report",
                "Actionable Suggestions List",
                "API Data",
            ],
            timestamp=datetime.now(),
        )

    async def _handle_methodology_query(self, query: ResearchQuery, entities: List[str]) -> QueryResponse:
        """Handle methodology recommendation queries."""
        research_goals = (
            [f"Study {entity}" for entity in entities] if entities else ["General genomics research"]
        )

        recommendations = await research_intelligence.recommend_methodologies(
            research_goals=research_goals, constraints=query.context or {}
        )

        answer = f"For your research goals involving {', '.join(entities) if entities else 'genomics'}, I recommend:\n\n"

        for i, rec in enumerate(recommendations[:3], 1):
            answer += f"{i}. **{rec.technique}** (Confidence: {rec.confidence:.1%})\n"
            answer += f"   - {rec.rationale}\n"
            answer += f"   - Expected outcomes: {', '.join(rec.expected_outcomes[:2])}\n\n"

        answer += "Each recommendation includes detailed resource requirements and alternative approaches."

        insights = [
            {
                "type": "methodology_recommendation",
                "technique": rec.technique,
                "confidence": rec.confidence,
                "rationale": rec.rationale,
                "required_resources": rec.required_resources,
                "expected_outcomes": rec.expected_outcomes,
            }
            for rec in recommendations
        ]

        return QueryResponse(
            query=query.query,
            answer=answer,
            insights=insights,
            data_sources=["Methodology Database", "Success Rate Analysis"],
            confidence_score=0.78,
            follow_up_suggestions=[
                "Compare these methodologies in detail",
                "Get cost and timeline estimates",
                "Find similar studies using these approaches",
            ],
            export_options=[
                "Methodology Report",
                "Resource Planning Sheet",
                "Protocol References",
            ],
            timestamp=datetime.now(),
        )

    async def _handle_comparison_query(self, query: ResearchQuery, entities: List[str]) -> QueryResponse:
        """Handle comparison queries."""
        if len(entities) < 2:
            entities = [
                "RNA-seq",
                "scRNA-seq",
                "ATAC-seq",
            ]  # Default comparison

        # Get comparison data (simplified - would integrate with comparative analysis widget)
        comparison_data = {
            "RNA-seq": {"resolution": 0.8, "cost": 0.9, "complexity": 0.6},
            "scRNA-seq": {"resolution": 0.95, "cost": 0.4, "complexity": 0.3},
            "ATAC-seq": {"resolution": 0.7, "cost": 0.7, "complexity": 0.7},
        }

        answer = f"Comparing {' vs '.join(entities[:3])}:\n\n"

        for entity in entities[:3]:
            if entity in comparison_data:
                data = comparison_data[entity]
                answer += f"**{entity}:**\n"
                answer += f"- Data Resolution: {data['resolution']:.1%}\n"
                answer += f"- Cost Effectiveness: {data['cost']:.1%}\n"
                answer += f"- Technical Complexity: {data['complexity']:.1%}\n\n"

        answer += (
            "Recommendation: Choose based on your specific research requirements and budget constraints."
        )

        insights = [
            {
                "type": "comparison",
                "entity": entity,
                "metrics": comparison_data.get(entity, {}),
                "recommendation": f"Best for specific use cases involving {entity}",
            }
            for entity in entities[:3]
        ]

        return QueryResponse(
            query=query.query,
            answer=answer,
            insights=insights,
            data_sources=[
                "Comparative Analysis Database",
                "Performance Metrics",
            ],
            confidence_score=0.82,
            follow_up_suggestions=[
                "Get detailed statistical comparison",
                "Find success stories for each approach",
                "Calculate cost-benefit analysis",
            ],
            export_options=[
                "Comparison Matrix",
                "Decision Tree",
                "Benchmark Report",
            ],
            timestamp=datetime.now(),
        )

    async def _handle_data_summary_query(self, query: ResearchQuery, entities: List[str]) -> QueryResponse:
        """Handle data summary queries."""
        entity = entities[0] if entities else "genomics research"

        # Get entity information from knowledge base
        if entities and entities[0] in research_intelligence.entity_knowledge_base:
            entity_data = research_intelligence.entity_knowledge_base[entities[0]]

            answer = f"Here's what I know about **{entity}**:\n\n"
            answer += f"- **Research Activity:** {entity_data.recent_activity:.1%} recent activity level\n"
            answer += f"- **Publications:** {entity_data.publications_count:,} related publications\n"
            answer += f"- **Datasets:** {entity_data.datasets_count:,} available datasets\n"
            answer += f"- **Category:** {entity_data.category.title()}\n\n"

            if entity_data.recent_activity < 0.5:
                answer += "⚠️ This area shows lower recent activity, potentially indicating research gaps or opportunities."
            else:
                answer += "✅ This is an active research area with ongoing studies and data generation."
        else:
            answer = f"Based on current research trends, **{entity}** represents an important area in genomics research with various ongoing studies and datasets available."

        insights = [
            {
                "type": "data_summary",
                "entity": entity,
                "activity_level": research_intelligence.entity_knowledge_base.get(
                    entity, None
                ).recent_activity
                if entity in research_intelligence.entity_knowledge_base
                else 0.5,
                "data_availability": "High"
                if entity in research_intelligence.entity_knowledge_base
                else "Unknown",
            }
        ]

        return QueryResponse(
            query=query.query,
            answer=answer,
            insights=insights,
            data_sources=["Entity Knowledge Base", "Publication Database"],
            confidence_score=0.75,
            follow_up_suggestions=[
                f"Find research gaps related to {entity}",
                f"Get methodology recommendations for studying {entity}",
                f"Explore cross-domain connections involving {entity}",
            ],
            export_options=[
                "Entity Report",
                "Data Summary",
                "Research Overview",
            ],
            timestamp=datetime.now(),
        )

    async def _handle_general_query(self, query: ResearchQuery, entities: List[str]) -> QueryResponse:
        """Handle general queries."""
        answer = "I can help you with various research insights! Here are some things you can ask me:\n\n"
        answer += '🎯 **Research Gaps**: "What research gaps exist in cancer genomics?"\n'
        answer += '🧪 **Methodology**: "What\'s the best method to study brain tissue?"\n'
        answer += '📊 **Comparisons**: "Compare RNA-seq vs scRNA-seq"\n'
        answer += '📈 **Trends**: "What are the emerging trends in genomics?"\n'
        answer += '📋 **Data Summary**: "Tell me about ATAC-seq"\n\n'
        answer += "I can provide AI-powered insights, methodology recommendations, and research intelligence!"

        insights = [
            {
                "type": "help",
                "available_queries": [
                    "Research gap identification",
                    "Methodology recommendations",
                    "Comparative analysis",
                    "Trend analysis",
                    "Data summaries",
                ],
            }
        ]

        return QueryResponse(
            query=query.query,
            answer=answer,
            insights=insights,
            data_sources=["Help System"],
            confidence_score=1.0,
            follow_up_suggestions=[
                "Try asking about research gaps in your field of interest",
                "Request methodology recommendations for your research goals",
                "Compare different research approaches",
            ],
            export_options=["Help Guide", "Query Examples"],
            timestamp=datetime.now(),
        )

    async def _handle_trends_query(self, query: ResearchQuery, entities: List[str]) -> QueryResponse:
        """Handle research trends queries."""
        answer = "Based on current research patterns, here are key trends:\n\n"
        answer += "📈 **Single-Cell Technologies**: Explosive growth in scRNA-seq and related methods\n"
        answer += "🧬 **Multi-Omics Integration**: Combining genomics, proteomics, and metabolomics\n"
        answer += "🤖 **AI in Genomics**: Machine learning for pattern discovery and drug development\n"
        answer += "🎯 **Precision Medicine**: Personalized treatments based on genetic profiles\n"
        answer += "🌍 **Population Genomics**: Large-scale studies across diverse populations\n\n"

        if entities:
            answer += f"Specifically for {', '.join(entities)}, there's increased focus on novel applications and cross-domain research."

        insights = [
            {
                "type": "trend_analysis",
                "trend": "Single-Cell Technologies",
                "growth_rate": "High",
                "impact": "Revolutionary insights into cellular heterogeneity",
            },
            {
                "type": "trend_analysis",
                "trend": "AI Integration",
                "growth_rate": "Very High",
                "impact": "Accelerated discovery and pattern recognition",
            },
        ]

        return QueryResponse(
            query=query.query,
            answer=answer,
            insights=insights,
            data_sources=["Trend Analysis Engine", "Publication Patterns"],
            confidence_score=0.80,
            follow_up_suggestions=[
                "Get methodology recommendations for trending approaches",
                "Find research gaps in emerging fields",
                "Compare traditional vs. emerging methods",
            ],
            export_options=["Trend Report", "Technology Roadmap"],
            timestamp=datetime.now(),
        )

    async def _personalize_response(self, response: QueryResponse, user_id: str) -> QueryResponse:
        """Personalize response based on user profile."""
        # Update user interaction
        interaction_data = {
            "query": response.query,
            "entities": self._extract_entities(response.query),
            "timestamp": datetime.now().isoformat(),
        }

        personalization_engine.update_user_profile(user_id, interaction_data)

        # Add personalized suggestions (simplified)
        response.follow_up_suggestions.append(
            "Based on your research history, you might also be interested in related cross-domain insights"
        )

        return response


# Initialize query engine
query_engine = ResearchQueryEngine()

# Query router
query_router = APIRouter(prefix="/api/research/query", tags=["research-queries"])


@query_router.post("/ask")
async def ask_research_question(query: ResearchQuery):
    """Ask a natural language research question and get comprehensive insights."""
    try:
        response = await query_engine.process_query(query)
        return {
            "success": True,
            "response": asdict(response),
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        logger.error(f"Error processing query: {e}")
        raise HTTPException(status_code=500, detail=f"Error processing query: {str(e)}")


@query_router.get("/examples")
async def get_query_examples():
    """Get example queries that users can ask."""
    return {
        "success": True,
        "examples": [
            {
                "category": "Research Gaps",
                "queries": [
                    "What research gaps exist in cancer genomics?",
                    "Are there underexplored areas in neuroscience?",
                    "What should I study in immunology?",
                ],
            },
            {
                "category": "Methodology",
                "queries": [
                    "What's the best method to study brain tissue?",
                    "Should I use RNA-seq or scRNA-seq for my cancer study?",
                    "Recommend approaches for studying gene expression",
                ],
            },
            {
                "category": "Comparisons",
                "queries": [
                    "Compare RNA-seq vs scRNA-seq",
                    "What's the difference between ATAC-seq and ChIP-seq?",
                    "Which is better for single-cell analysis?",
                ],
            },
            {
                "category": "Data Summary",
                "queries": [
                    "Tell me about ATAC-seq",
                    "Summarize what's known about Alzheimer's research",
                    "What information is available on heart studies?",
                ],
            },
            {
                "category": "Trends",
                "queries": [
                    "What are emerging trends in genomics?",
                    "What's popular in cancer research?",
                    "Recent developments in single-cell technologies",
                ],
            },
        ],
    }
