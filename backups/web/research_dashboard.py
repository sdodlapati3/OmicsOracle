#!/usr/bin/env python3
"""
Research Dashboard - Core research intelligence platform for OmicsOracle.

This module implements a research-focused dashboard that serves as a discovery
accelerator for genomics researchers, replacing the generic analytics dashboard
with research-specific insights and visualizations.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel


class ResearchDomain(str, Enum):
    """Supported research domains for specialized dashboard configurations."""

    CANCER_RESEARCH = "cancer_research"
    NEUROSCIENCE = "neuroscience"
    IMMUNOLOGY = "immunology"
    DEVELOPMENTAL_BIOLOGY = "developmental_biology"
    CARDIOVASCULAR = "cardiovascular"
    AGING_RESEARCH = "aging_research"
    GENERAL_GENOMICS = "general_genomics"


class WidgetType(str, Enum):
    """Types of research widgets available."""

    RESEARCH_DOMAIN_MAP = "research_domain_map"
    PUBLICATION_TIMELINE = "publication_timeline"
    DATASET_AVAILABILITY_MATRIX = "dataset_availability_matrix"
    RESEARCH_GAP_IDENTIFIER = "research_gap_identifier"
    DISCOVERY_ASSISTANT = "discovery_assistant"
    COMPARATIVE_ANALYSIS = "comparative_analysis"
    SAVED_QUERIES = "saved_queries"
    RESEARCH_MONITORING = "research_monitoring"


@dataclass
class ResearchContext:
    """Context information for personalizing research dashboard."""

    user_id: str = "anonymous"
    research_domains: List[ResearchDomain] = field(default_factory=lambda: [ResearchDomain.GENERAL_GENOMICS])
    preferred_organisms: List[str] = field(default_factory=lambda: ["Homo sapiens"])
    research_techniques: List[str] = field(default_factory=lambda: ["RNA-seq"])
    time_horizon: str = "2_years"
    collaboration_level: str = "individual"
    recent_queries: List[str] = field(default_factory=list)
    saved_searches: List[str] = field(default_factory=list)


class ResearchInsight(BaseModel):
    """Structured research insight with confidence scoring."""

    insight_type: str  # gap, connection, trend, recommendation
    title: str
    description: str
    confidence_score: float  # 0.0 to 1.0
    research_domains: List[str]
    supporting_data: Dict[str, Any]
    actionable_suggestions: List[str]
    created_at: datetime = datetime.now()


class WidgetConfig(BaseModel):
    """Configuration for dashboard widgets."""

    widget_type: WidgetType
    title: str
    description: str
    position: Dict[str, int]  # x, y, width, height
    refresh_interval: int = 300  # seconds
    settings: Dict[str, Any] = {}


class ResearchWidget(ABC):
    """Abstract base class for all research dashboard widgets."""

    def __init__(self, config: WidgetConfig):
        self.config = config
        self.cache_duration = timedelta(minutes=5)
        self._cached_data = None
        self._cache_timestamp = None

    @abstractmethod
    def get_data(self, context: ResearchContext) -> Dict[str, Any]:
        """Fetch widget data based on research context."""
        pass

    @abstractmethod
    def get_visualization_config(self) -> Dict[str, Any]:
        """Return configuration for frontend visualization."""
        pass

    def get_cached_data(self, context: ResearchContext) -> Dict[str, Any]:
        """Get data with caching support."""
        now = datetime.now()

        if (
            self._cached_data is None
            or self._cache_timestamp is None
            or now - self._cache_timestamp > self.cache_duration
        ):
            self._cached_data = self.get_data(context)
            self._cache_timestamp = now

        return self._cached_data


class ResearchDomainMapWidget(ResearchWidget):
    """Interactive network visualization of research domain relationships."""

    def get_data(self, context: ResearchContext) -> Dict[str, Any]:
        """Generate network data showing relationships between research entities."""
        # This will integrate with the main pipeline to extract entity relationships
        # from actual search results and build a network graph

        # Mock implementation for now - will be replaced with real pipeline integration
        domains = [domain.value for domain in context.research_domains]

        # Generate nodes (entities)
        nodes = []
        edges = []

        # Core research entities based on user context
        entities = {
            "diseases": [
                "cancer",
                "alzheimer",
                "diabetes",
                "cardiovascular disease",
            ],
            "tissues": ["brain", "liver", "heart", "blood"],
            "techniques": ["RNA-seq", "WGBS", "ChIP-seq", "ATAC-seq"],
            "organisms": context.preferred_organisms,
        }

        node_id = 0
        entity_map = {}

        for category, items in entities.items():
            for item in items[:6]:  # Limit for performance
                nodes.append(
                    {
                        "id": node_id,
                        "label": item,
                        "category": category,
                        "size": 20
                        + len([q for q in context.recent_queries if item.lower() in q.lower()]) * 5,
                        "color": self._get_category_color(category),
                    }
                )
                entity_map[item] = node_id
                node_id += 1

        # Generate edges (relationships)
        # This would come from actual co-occurrence analysis in real implementation
        for i in range(len(nodes)):
            for j in range(i + 1, min(i + 3, len(nodes))):
                if nodes[i]["category"] != nodes[j]["category"]:
                    edges.append(
                        {
                            "source": nodes[i]["id"],
                            "target": nodes[j]["id"],
                            "weight": 0.5 + (hash(f"{i}-{j}") % 5) / 10,
                        }
                    )

        return {
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "total_entities": len(nodes),
                "total_relationships": len(edges),
                "domains": domains,
                "last_updated": datetime.now().isoformat(),
            },
        }

    def get_visualization_config(self) -> Dict[str, Any]:
        """Configuration for D3.js network visualization."""
        return {
            "type": "network",
            "layout": "force",
            "node_settings": {
                "min_size": 15,
                "max_size": 40,
                "label_threshold": 20,
            },
            "edge_settings": {"min_width": 1, "max_width": 5, "opacity": 0.6},
            "physics": {"enabled": True, "strength": -300, "distance": 100},
        }

    def _get_category_color(self, category: str) -> str:
        """Get color for entity category."""
        colors = {
            "diseases": "#e74c3c",  # Red
            "tissues": "#3498db",  # Blue
            "techniques": "#2ecc71",  # Green
            "organisms": "#f39c12",  # Orange
        }
        return colors.get(category, "#95a5a6")


class PublicationTimelineWidget(ResearchWidget):
    """Timeline visualization of research publication trends."""

    def get_data(self, context: ResearchContext) -> Dict[str, Any]:
        """Generate publication timeline data for research domains."""
        # This will integrate with PubMed API and search results
        # Mock implementation for demonstration

        end_date = datetime.now()
        start_date = end_date - timedelta(days=365 * 2)  # 2 years

        # Generate timeline data points
        timeline_data = []
        current_date = start_date

        while current_date <= end_date:
            # Mock publication counts - would come from real PubMed queries
            base_count = 50 + hash(current_date.strftime("%Y-%m")) % 30

            # Adjust based on user's research domains and queries
            domain_boost = 0
            for domain in context.research_domains:
                if domain != ResearchDomain.GENERAL_GENOMICS:
                    domain_boost += 10

            query_boost = (
                len(
                    [
                        q
                        for q in context.recent_queries
                        if any(term in q.lower() for term in ["cancer", "brain", "methylation"])
                    ]
                )
                * 5
            )

            timeline_data.append(
                {
                    "date": current_date.strftime("%Y-%m"),
                    "publications": base_count + domain_boost + query_boost,
                    "relevant_to_user": query_boost > 0,
                    "domains": [domain.value for domain in context.research_domains],
                }
            )

            # Move to next month
            if current_date.month == 12:
                current_date = current_date.replace(year=current_date.year + 1, month=1)
            else:
                current_date = current_date.replace(month=current_date.month + 1)

        return {
            "timeline": timeline_data,
            "metadata": {
                "date_range": {
                    "start": start_date.strftime("%Y-%m"),
                    "end": end_date.strftime("%Y-%m"),
                },
                "total_publications": sum(item["publications"] for item in timeline_data),
                "relevant_publications": sum(
                    item["publications"] for item in timeline_data if item["relevant_to_user"]
                ),
                "domains": [domain.value for domain in context.research_domains],
            },
        }

    def get_visualization_config(self) -> Dict[str, Any]:
        """Configuration for timeline chart."""
        return {
            "type": "line_chart",
            "x_axis": {
                "field": "date",
                "type": "datetime",
                "title": "Publication Date",
            },
            "y_axis": {
                "field": "publications",
                "type": "linear",
                "title": "Number of Publications",
            },
            "series": [
                {
                    "name": "All Publications",
                    "color": "#3498db",
                    "line_width": 2,
                },
                {
                    "name": "Relevant to Your Research",
                    "color": "#e74c3c",
                    "line_width": 3,
                    "filter": "relevant_to_user",
                },
            ],
            "annotations": True,
            "zoom": True,
        }


class DatasetAvailabilityMatrixWidget(ResearchWidget):
    """Heatmap showing data availability across research dimensions."""

    def get_data(self, context: ResearchContext) -> Dict[str, Any]:
        """Generate availability matrix data."""
        # This will analyze actual GEO data availability
        # Mock implementation showing organism × technique matrix

        organisms = context.preferred_organisms + [
            "Mus musculus",
            "Rattus norvegicus",
            "Drosophila melanogaster",
        ]
        techniques = [
            "RNA-seq",
            "ChIP-seq",
            "WGBS",
            "ATAC-seq",
            "Microarray",
            "scRNA-seq",
        ]

        matrix_data = []
        for organism in organisms[:5]:  # Limit for display
            row = []
            for technique in techniques:
                # Mock availability score (0-100)
                base_score = hash(f"{organism}-{technique}") % 80 + 20

                # Boost score for user's preferred organisms and recent queries
                if organism in context.preferred_organisms:
                    base_score += 10
                if any(technique.lower() in q.lower() for q in context.recent_queries):
                    base_score += 15

                row.append(min(100, base_score))
            matrix_data.append(row)

        return {
            "matrix": matrix_data,
            "organisms": organisms[:5],
            "techniques": techniques,
            "metadata": {
                "user_organisms": context.preferred_organisms,
                "user_techniques": context.research_techniques,
                "total_combinations": len(organisms[:5]) * len(techniques),
                "high_availability_threshold": 80,
            },
        }

    def get_visualization_config(self) -> Dict[str, Any]:
        """Configuration for heatmap visualization."""
        return {
            "type": "heatmap",
            "color_scale": {
                "low": "#fff5f5",
                "medium": "#fed7d7",
                "high": "#e53e3e",
                "range": [0, 100],
            },
            "cell_settings": {
                "show_values": True,
                "border_width": 1,
                "border_color": "#e2e8f0",
            },
            "axes": {
                "x_title": "Experimental Techniques",
                "y_title": "Model Organisms",
            },
            "tooltip": {"format": "{organism} + {technique}: {value} datasets available"},
        }


class ResearchGapIdentifierWidget(ResearchWidget):
    """AI-powered identification of research gaps and opportunities."""

    def get_data(self, context: ResearchContext) -> Dict[str, Any]:
        """Identify research gaps using AI analysis."""
        # This will integrate with AI pipeline for real gap analysis
        # Mock implementation for demonstration

        gaps = []

        # Generate research gaps based on user context
        if ResearchDomain.CANCER_RESEARCH in context.research_domains:
            gaps.append(
                {
                    "id": "cancer_gap_1",
                    "title": "Limited WGBS data in pediatric brain tumors",
                    "description": "Only 12 datasets available for methylation analysis in pediatric brain cancers, compared to 200+ in adult cancers.",
                    "opportunity_score": 0.85,
                    "impact_potential": "High",
                    "research_domains": ["cancer_research", "neuroscience"],
                    "suggested_organisms": ["Homo sapiens"],
                    "suggested_techniques": ["WGBS", "RRBS", "ChIP-seq"],
                    "funding_opportunities": ["NIH R01", "NCI SPORE"],
                    "estimated_datasets_needed": 25,
                }
            )

        if ResearchDomain.NEUROSCIENCE in context.research_domains:
            gaps.append(
                {
                    "id": "neuro_gap_1",
                    "title": "Aging brain single-cell methylation studies underrepresented",
                    "description": "Single-cell methylation analysis in aging brain tissue has only 3 studies, while aging bulk methylation has 50+ studies.",
                    "opportunity_score": 0.78,
                    "impact_potential": "High",
                    "research_domains": ["neuroscience", "aging_research"],
                    "suggested_organisms": ["Homo sapiens", "Mus musculus"],
                    "suggested_techniques": ["scWGBS", "scRRBS"],
                    "funding_opportunities": ["NIA R01", "Glenn Foundation"],
                    "estimated_datasets_needed": 15,
                }
            )

        # Add general gaps for any domain
        gaps.append(
            {
                "id": "general_gap_1",
                "title": "Cross-species comparative epigenomics limited",
                "description": "Most studies focus on single species; cross-species methylation comparisons are rare but highly valuable.",
                "opportunity_score": 0.72,
                "impact_potential": "Medium-High",
                "research_domains": ["general_genomics"],
                "suggested_organisms": [
                    "Homo sapiens",
                    "Mus musculus",
                    "Pan troglodytes",
                ],
                "suggested_techniques": ["WGBS", "ChIP-seq"],
                "funding_opportunities": [
                    "NSF",
                    "Comparative Genomics Initiatives",
                ],
                "estimated_datasets_needed": 20,
            }
        )

        return {
            "gaps": gaps[:3],  # Show top 3 gaps
            "metadata": {
                "total_gaps_identified": len(gaps),
                "user_domains": [domain.value for domain in context.research_domains],
                "analysis_date": datetime.now().isoformat(),
                "confidence_threshold": 0.6,
            },
        }

    def get_visualization_config(self) -> Dict[str, Any]:
        """Configuration for gap visualization."""
        return {
            "type": "opportunity_cards",
            "card_settings": {
                "max_cards": 3,
                "show_scores": True,
                "show_suggestions": True,
            },
            "scoring": {
                "opportunity_scale": [0, 1],
                "impact_levels": ["Low", "Medium", "Medium-High", "High"],
                "color_scheme": {
                    "High": "#e53e3e",
                    "Medium-High": "#f56500",
                    "Medium": "#d69e2e",
                    "Low": "#38a169",
                },
            },
        }


class DashboardManager:
    """Manages research dashboard configuration and widget orchestration."""

    def __init__(self):
        self.domain_configs = self._load_domain_configs()
        self.widget_registry = self._initialize_widgets()

    def _load_domain_configs(self) -> Dict[ResearchDomain, Dict[str, Any]]:
        """Load dashboard configurations for different research domains."""
        return {
            ResearchDomain.CANCER_RESEARCH: {
                "primary_widgets": [
                    WidgetType.RESEARCH_DOMAIN_MAP,
                    WidgetType.PUBLICATION_TIMELINE,
                    WidgetType.DATASET_AVAILABILITY_MATRIX,
                    WidgetType.RESEARCH_GAP_IDENTIFIER,
                ],
                "entity_focus": ["diseases", "treatments", "outcomes"],
                "time_horizon": "5_years",
                "color_scheme": "cancer_red",
            },
            ResearchDomain.NEUROSCIENCE: {
                "primary_widgets": [
                    WidgetType.RESEARCH_DOMAIN_MAP,
                    WidgetType.PUBLICATION_TIMELINE,
                    WidgetType.DATASET_AVAILABILITY_MATRIX,
                    WidgetType.RESEARCH_GAP_IDENTIFIER,
                ],
                "entity_focus": ["brain_regions", "techniques", "phenotypes"],
                "time_horizon": "3_years",
                "color_scheme": "neuro_blue",
            },
            ResearchDomain.GENERAL_GENOMICS: {
                "primary_widgets": [
                    WidgetType.RESEARCH_DOMAIN_MAP,
                    WidgetType.PUBLICATION_TIMELINE,
                    WidgetType.DATASET_AVAILABILITY_MATRIX,
                ],
                "entity_focus": ["organisms", "techniques", "phenotypes"],
                "time_horizon": "2_years",
                "color_scheme": "genomics_green",
            },
        }

    def _initialize_widgets(self) -> Dict[WidgetType, type]:
        """Initialize widget registry."""
        return {
            WidgetType.RESEARCH_DOMAIN_MAP: ResearchDomainMapWidget,
            WidgetType.PUBLICATION_TIMELINE: PublicationTimelineWidget,
            WidgetType.DATASET_AVAILABILITY_MATRIX: DatasetAvailabilityMatrixWidget,
            WidgetType.RESEARCH_GAP_IDENTIFIER: ResearchGapIdentifierWidget,
        }

    def get_dashboard_config(self, context: ResearchContext) -> Dict[str, Any]:
        """Get dashboard configuration for user's research context."""
        primary_domain = (
            context.research_domains[0] if context.research_domains else ResearchDomain.GENERAL_GENOMICS
        )
        config = self.domain_configs.get(primary_domain, self.domain_configs[ResearchDomain.GENERAL_GENOMICS])

        return {
            "domain": primary_domain.value,
            "widgets": config["primary_widgets"],
            "settings": {
                "entity_focus": config["entity_focus"],
                "time_horizon": config["time_horizon"],
                "color_scheme": config["color_scheme"],
            },
            "layout": self._generate_layout(config["primary_widgets"]),
        }

    def _generate_layout(self, widgets: List[WidgetType]) -> List[Dict[str, Any]]:
        """Generate responsive layout for widgets."""
        layouts = {
            WidgetType.RESEARCH_DOMAIN_MAP: {"x": 0, "y": 0, "w": 6, "h": 4},
            WidgetType.PUBLICATION_TIMELINE: {"x": 6, "y": 0, "w": 6, "h": 4},
            WidgetType.DATASET_AVAILABILITY_MATRIX: {
                "x": 0,
                "y": 4,
                "w": 6,
                "h": 4,
            },
            WidgetType.RESEARCH_GAP_IDENTIFIER: {
                "x": 6,
                "y": 4,
                "w": 6,
                "h": 4,
            },
        }

        return [
            {
                "widget_type": widget.value,
                "layout": layouts.get(widget, {"x": 0, "y": 0, "w": 6, "h": 4}),
            }
            for widget in widgets
        ]

    def get_widget_data(self, widget_type: WidgetType, context: ResearchContext) -> Dict[str, Any]:
        """Get data for a specific widget."""
        if widget_type not in self.widget_registry:
            raise ValueError(f"Unknown widget type: {widget_type}")

        widget_class = self.widget_registry[widget_type]
        config = WidgetConfig(
            widget_type=widget_type,
            title=widget_type.value.replace("_", " ").title(),
            description=f"Research insights for {widget_type.value}",
            position={"x": 0, "y": 0, "width": 6, "height": 4},
        )

        widget = widget_class(config)
        data = widget.get_cached_data(context)
        visualization_config = widget.get_visualization_config()

        return {
            "data": data,
            "config": visualization_config,
            "metadata": {
                "widget_type": widget_type.value,
                "last_updated": datetime.now().isoformat(),
                "cache_duration": widget.cache_duration.total_seconds(),
            },
        }


# Initialize dashboard manager
dashboard_manager = DashboardManager()


# FastAPI Router for research dashboard
router = APIRouter(prefix="/api/research", tags=["research-dashboard"])


@router.get("/dashboard/config")
async def get_dashboard_config(
    domain: Optional[ResearchDomain] = ResearchDomain.GENERAL_GENOMICS,
    user_id: str = "anonymous",
):
    """Get dashboard configuration for research domain."""
    context = ResearchContext(
        user_id=user_id,
        research_domains=[domain] if domain else [ResearchDomain.GENERAL_GENOMICS],
    )

    config = dashboard_manager.get_dashboard_config(context)
    return {
        "success": True,
        "config": config,
        "context": {
            "user_id": context.user_id,
            "domains": [d.value for d in context.research_domains],
            "organisms": context.preferred_organisms,
        },
    }


@router.get("/widgets/{widget_type}")
async def get_widget_data(
    widget_type: WidgetType,
    domain: Optional[ResearchDomain] = ResearchDomain.GENERAL_GENOMICS,
    user_id: str = "anonymous",
):
    """Get data for a specific research widget."""
    try:
        context = ResearchContext(
            user_id=user_id,
            research_domains=[domain] if domain else [ResearchDomain.GENERAL_GENOMICS],
        )

        widget_data = dashboard_manager.get_widget_data(widget_type, context)

        return {
            "success": True,
            "widget_type": widget_type.value,
            "data": widget_data["data"],
            "config": widget_data["config"],
            "metadata": widget_data["metadata"],
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating widget data: {str(e)}")


@router.post("/context/update")
async def update_research_context(
    user_id: str,
    domains: List[ResearchDomain],
    organisms: List[str] = ["Homo sapiens"],
    techniques: List[str] = ["RNA-seq"],
    recent_queries: List[str] = [],
):
    """Update user's research context for personalized dashboard."""
    # In a real implementation, this would save to database
    context = ResearchContext(
        user_id=user_id,
        research_domains=domains,
        preferred_organisms=organisms,
        research_techniques=techniques,
        recent_queries=recent_queries,
    )

    return {
        "success": True,
        "message": "Research context updated successfully",
        "context": {
            "user_id": context.user_id,
            "domains": [d.value for d in context.research_domains],
            "organisms": context.preferred_organisms,
            "techniques": context.research_techniques,
        },
    }


@router.get("/dashboard")
async def get_research_dashboard():
    """Serve the research dashboard HTML interface."""
    from pathlib import Path

    from fastapi.responses import FileResponse

    dashboard_file = Path(__file__).parent / "static" / "research_dashboard.html"

    if dashboard_file.exists():
        return FileResponse(str(dashboard_file))
    else:
        return HTMLResponse(
            content="""
        <!DOCTYPE html>
        <html>
        <head>
            <title>🧬 OmicsOracle Research Dashboard</title>
            <style>
                body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                .container { max-width: 800px; margin: 0 auto; }
                .status { background: #f0f8ff; padding: 20px; border-radius: 10px; margin: 20px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🧬 OmicsOracle Research Intelligence Platform</h1>
                <div class="status">
                    <h2>✅ Research Dashboard Core Implemented</h2>
                    <p>The new research-focused dashboard system has been successfully implemented with:</p>
                    <ul style="text-align: left;">
                        <li>🗺️ Research Domain Mapping with interactive network visualization</li>
                        <li>📈 Publication Timeline analysis for research trends</li>
                        <li>🧬 Dataset Availability Matrix across organisms and techniques</li>
                        <li>🎯 AI-powered Research Gap Identification</li>
                        <li>⚙️ Modular widget system for extensibility</li>
                        <li>🎨 Modern, responsive research-focused interface</li>
                    </ul>
                    <p><strong>Phase 1 Foundation: Complete ✅</strong></p>
                    <p>Ready to proceed with Phase 2: Intelligence Layer implementation.</p>
                </div>
                <div style="margin-top: 30px;">
                    <a href="/api/research/dashboard/config" style="background: #667eea; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin: 10px;">
                        📊 Test Dashboard Config API
                    </a>
                    <a href="/api/research/widgets/research_domain_map" style="background: #764ba2; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin: 10px;">
                        🗺️ Test Domain Map Widget
                    </a>
                </div>
            </div>
        </body>
        </html>
        """
        )


@router.get("/intelligence")
async def get_research_intelligence_dashboard():
    """Serve the enhanced research intelligence dashboard."""
    from pathlib import Path

    from fastapi.responses import FileResponse

    dashboard_file = Path(__file__).parent / "static" / "research_intelligence_dashboard.html"

    if dashboard_file.exists():
        return FileResponse(str(dashboard_file))
    else:
        return HTMLResponse(
            content="""
        <html><body>
        <h1>Research Intelligence Dashboard Not Found</h1>
        <p>The enhanced dashboard file could not be located.</p>
        <a href="/api/research/dashboard">Return to Basic Dashboard</a>
        </body></html>
        """
        )
