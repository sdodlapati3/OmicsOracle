"""
Visualization Agent for Futuristic Interface

Handles advanced data visualization and interactive charts
"""

import logging
from typing import Dict, List, Optional

from ..models.futuristic_models import (
    AgentMessage,
    AgentType,
    VisualizationData,
)
from .base import AgentCapability, BaseAgent, MessageType

logger = logging.getLogger(__name__)


class VisualizationAgent(BaseAgent):
    """Advanced visualization agent"""

    def __init__(self, agent_id: str):
        super().__init__(agent_id, AgentType.VISUALIZATION)
        self.capabilities = [
            AgentCapability.NETWORK_VISUALIZATION,
            AgentCapability.TIMELINE_VISUALIZATION,
            AgentCapability.STATISTICAL_CHARTS,
        ]

    async def initialize(self) -> bool:
        """Initialize the visualization agent"""
        try:
            logger.info(f"[CHART] Initializing visualization agent {self.agent_id}")
            return True
        except Exception as e:
            logger.error(
                f"[ERROR] Failed to initialize visualization agent {self.agent_id}: {e}"
            )
            return False

    async def cleanup(self) -> None:
        """Clean up visualization agent resources"""
        logger.info(f"[CLEANUP] Cleaning up visualization agent {self.agent_id}")

    async def process_message(
        self, message: AgentMessage
    ) -> Optional[AgentMessage]:
        """Process visualization-related messages"""
        try:
            if message.type == MessageType.VISUALIZE_REQUEST:
                return await self._handle_visualization_request(message)
            elif message.type == MessageType.HEALTH_CHECK:
                return await self._handle_health_check(message)
            else:
                return None

        except Exception as e:
            logger.error(f"Visualization agent error: {e}")
            return AgentMessage(
                type=MessageType.ERROR,
                sender_id=self.agent_id,
                target_id=message.sender_id,
                payload={"error": str(e)},
            )

    async def _handle_visualization_request(
        self, message: AgentMessage
    ) -> AgentMessage:
        """Handle visualization request"""
        data = message.payload.get("data", [])
        viz_type = message.payload.get("visualization_type", "chart")

        visualizations = await self._generate_visualizations(data, viz_type)

        return AgentMessage(
            type=MessageType.VISUALIZE_RESPONSE,
            sender_id=self.agent_id,
            target_id=message.sender_id,
            payload={
                "job_id": message.payload.get("job_id"),
                "visualizations": [viz.dict() for viz in visualizations],
                "visualization_type": viz_type,
            },
        )

    async def _generate_visualizations(
        self, data: List[Dict], viz_type: str
    ) -> List[VisualizationData]:
        """Generate visualizations from data"""
        visualizations = []

        if not data:
            return visualizations

        # Timeline visualization
        timeline_viz = await self._create_timeline_visualization(data)
        if timeline_viz:
            visualizations.append(timeline_viz)

        # Statistical charts
        stats_viz = await self._create_statistical_charts(data)
        if stats_viz:
            visualizations.append(stats_viz)

        # Network visualization
        if len(data) > 5:  # Only for larger datasets
            network_viz = await self._create_network_visualization(data)
            if network_viz:
                visualizations.append(network_viz)

        return visualizations

    async def _create_timeline_visualization(
        self, data: List[Dict]
    ) -> Optional[VisualizationData]:
        """Create timeline visualization"""
        timeline_data = []

        for item in data:
            pub_date = item.get("publication_date")
            if pub_date:
                timeline_data.append(
                    {
                        "date": str(pub_date)[:10],  # YYYY-MM-DD format
                        "title": item.get("title", "Unknown"),
                        "authors": item.get("authors", []),
                        "id": item.get("id", ""),
                    }
                )

        if not timeline_data:
            return None

        return VisualizationData(
            type="timeline",
            title="Publication Timeline",
            data={
                "events": timeline_data,
                "dateFormat": "%Y-%m-%d",
                "height": 400,
            },
            config={"interactive": True, "zoomable": True, "tooltip": True},
        )

    async def _create_statistical_charts(
        self, data: List[Dict]
    ) -> Optional[VisualizationData]:
        """Create statistical charts"""
        # Analyze publication years
        years = {}
        sources = {}

        for item in data:
            # Count by year
            pub_date = item.get("publication_date", "")
            if len(pub_date) >= 4:
                year = pub_date[:4]
                if year.isdigit():
                    years[year] = years.get(year, 0) + 1

            # Count by source
            source = item.get("source", "Unknown")
            sources[source] = sources.get(source, 0) + 1

        charts = []

        # Year distribution chart
        if years:
            charts.append(
                {
                    "type": "bar",
                    "title": "Publications by Year",
                    "data": {
                        "labels": list(years.keys()),
                        "datasets": [
                            {
                                "label": "Publications",
                                "data": list(years.values()),
                                "backgroundColor": "rgba(54, 162, 235, 0.6)",
                            }
                        ],
                    },
                }
            )

        # Source distribution chart
        if sources:
            charts.append(
                {
                    "type": "pie",
                    "title": "Publications by Source",
                    "data": {
                        "labels": list(sources.keys()),
                        "datasets": [
                            {
                                "data": list(sources.values()),
                                "backgroundColor": [
                                    "#FF6384",
                                    "#36A2EB",
                                    "#FFCE56",
                                    "#4BC0C0",
                                    "#9966FF",
                                ],
                            }
                        ],
                    },
                }
            )

        if not charts:
            return None

        return VisualizationData(
            type="charts",
            title="Statistical Analysis",
            data={"charts": charts},
            config={"responsive": True, "maintainAspectRatio": False},
        )

    async def _create_network_visualization(
        self, data: List[Dict]
    ) -> Optional[VisualizationData]:
        """Create network visualization of relationships"""
        nodes = []
        links = []

        # Create nodes from publications
        for i, item in enumerate(
            data[:20]
        ):  # Limit to first 20 for performance
            nodes.append(
                {
                    "id": item.get("id", f"node_{i}"),
                    "title": item.get("title", "Unknown")[
                        :50
                    ],  # Truncate title
                    "group": self._get_topic_group(item),
                    "value": len(item.get("authors", []))
                    + 1,  # Node size based on author count
                }
            )

        # Create links based on shared authors or keywords
        for i, item1 in enumerate(data[:20]):
            for j, item2 in enumerate(data[i + 1 : 21], i + 1):
                similarity = self._calculate_similarity(item1, item2)
                if similarity > 0.3:  # Threshold for connection
                    links.append(
                        {
                            "source": item1.get("id", f"node_{i}"),
                            "target": item2.get("id", f"node_{j}"),
                            "value": similarity,
                        }
                    )

        if not nodes:
            return None

        return VisualizationData(
            type="network",
            title="Publication Network",
            data={"nodes": nodes, "links": links},
            config={
                "width": 800,
                "height": 600,
                "charge": -300,
                "linkDistance": 50,
            },
        )

    def _get_topic_group(self, item: Dict) -> str:
        """Classify item into topic group for visualization"""
        title = item.get("title", "").lower()
        abstract = item.get("abstract", "").lower()
        text = f"{title} {abstract}"

        if any(term in text for term in ["covid", "coronavirus", "sars"]):
            return "covid"
        elif any(term in text for term in ["cancer", "tumor", "oncology"]):
            return "cancer"
        elif any(
            term in text for term in ["gene", "genetic", "genomic", "dna"]
        ):
            return "genetics"
        elif any(term in text for term in ["drug", "therapy", "treatment"]):
            return "therapeutics"
        else:
            return "general"

    def _calculate_similarity(self, item1: Dict, item2: Dict) -> float:
        """Calculate similarity between two items"""
        score = 0.0

        # Check for shared authors
        authors1 = set(item1.get("authors", []))
        authors2 = set(item2.get("authors", []))
        if authors1 and authors2:
            shared_authors = len(authors1.intersection(authors2))
            if shared_authors > 0:
                score += shared_authors * 0.3

        # Check for similar topics
        if self._get_topic_group(item1) == self._get_topic_group(item2):
            score += 0.2

        # Check for keyword similarity (simplified)
        title1_words = set(item1.get("title", "").lower().split())
        title2_words = set(item2.get("title", "").lower().split())
        if title1_words and title2_words:
            shared_words = len(title1_words.intersection(title2_words))
            if shared_words > 1:
                score += shared_words * 0.1

        return min(1.0, score)

    async def _handle_health_check(self, message: AgentMessage) -> AgentMessage:
        """Handle health check request"""
        return AgentMessage(
            type="health_response",
            sender_id=self.agent_id,
            target_id=message.sender_id,
            payload={"status": "healthy", "capabilities": self.capabilities},
        )
