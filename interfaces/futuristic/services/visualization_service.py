"""
Enhanced Data Visualization Service for Futuristic Interface

Provides interactive charts, network visualizations, and real-time plots
using modern web technologies and D3.js integration
"""

import asyncio
import json
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel
from services.logging_service import futuristic_logger


class VisualizationType(str, Enum):
    """Types of visualizations available"""

    SCATTER_PLOT = "scatter_plot"
    LINE_CHART = "line_chart"
    BAR_CHART = "bar_chart"
    HEATMAP = "heatmap"
    NETWORK_GRAPH = "network_graph"
    TIMELINE = "timeline"
    HISTOGRAM = "histogram"
    BOX_PLOT = "box_plot"
    VOLCANO_PLOT = "volcano_plot"
    PATHWAY_MAP = "pathway_map"


class VisualizationConfig(BaseModel):
    """Configuration for a visualization"""

    viz_type: VisualizationType
    title: str
    width: int = 800
    height: int = 600
    interactive: bool = True
    theme: str = "dark"
    animation: bool = True
    export_formats: List[str] = ["png", "svg", "json"]


class DataPoint(BaseModel):
    """Individual data point for visualizations"""

    x: Union[float, str, datetime]
    y: Union[float, str]
    label: Optional[str] = None
    color: Optional[str] = None
    size: Optional[float] = None
    metadata: Dict[str, Any] = {}


class VisualizationData(BaseModel):
    """Data structure for visualizations"""

    datasets: List[Dict[str, Any]]
    labels: Optional[List[str]] = None
    colors: Optional[List[str]] = None
    metadata: Dict[str, Any] = {}


class EnhancedVisualizationService:
    """Advanced visualization service with real-time updates"""

    def __init__(self):
        self.active_visualizations: Dict[str, Dict] = {}
        self.update_callbacks = []
        self.color_palettes = {
            "default": ["#4ECDC4", "#45B7D1", "#96CEB4", "#FECA57", "#FF6B6B"],
            "scientific": [
                "#1f77b4",
                "#ff7f0e",
                "#2ca02c",
                "#d62728",
                "#9467bd",
            ],
            "omics": ["#e41a1c", "#377eb8", "#4daf4a", "#984ea3", "#ff7f00"],
            "gradient": ["#3b82f6", "#6366f1", "#8b5cf6", "#a855f7", "#c084fc"],
        }

        futuristic_logger.info("[DESIGN] Enhanced Visualization Service initialized")

    def add_update_callback(self, callback):
        """Add callback for real-time visualization updates"""
        self.update_callbacks.append(callback)

    async def _send_update(self, viz_id: str, update_data: Dict):
        """Send real-time visualization update"""
        for callback in self.update_callbacks:
            try:
                await callback(
                    {
                        "type": "visualization_update",
                        "viz_id": viz_id,
                        "data": update_data,
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                )
            except Exception as e:
                futuristic_logger.error(
                    f"Error sending visualization update: {e}"
                )

    async def create_scatter_plot(
        self,
        data: List[DataPoint],
        config: VisualizationConfig,
        viz_id: Optional[str] = None,
    ) -> Dict:
        """Create an interactive scatter plot"""

        if not viz_id:
            viz_id = f"scatter_{len(self.active_visualizations)}"

        # Prepare data for D3.js
        plot_data = {
            "type": "scatter",
            "id": viz_id,
            "config": config.dict(),
            "data": [point.dict() for point in data],
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Add color palette
        if not plot_data["data"] or not any(
            p.get("color") for p in plot_data["data"]
        ):
            colors = self.color_palettes.get(
                config.theme, self.color_palettes["default"]
            )
            for i, point in enumerate(plot_data["data"]):
                point["color"] = colors[i % len(colors)]

        self.active_visualizations[viz_id] = plot_data
        await self._send_update(viz_id, plot_data)

        futuristic_logger.info(
            f"[CHART] Created scatter plot '{config.title}' with {len(data)} points"
        )
        return plot_data

    async def create_network_graph(
        self,
        nodes: List[Dict],
        edges: List[Dict],
        config: VisualizationConfig,
        viz_id: Optional[str] = None,
    ) -> Dict:
        """Create an interactive network graph"""

        if not viz_id:
            viz_id = f"network_{len(self.active_visualizations)}"

        # Prepare network data
        network_data = {
            "type": "network",
            "id": viz_id,
            "config": config.dict(),
            "nodes": nodes,
            "edges": edges,
            "layout": "force",  # Can be force, circular, hierarchical
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Add node colors if not specified
        colors = self.color_palettes.get(
            config.theme, self.color_palettes["default"]
        )
        for i, node in enumerate(network_data["nodes"]):
            if "color" not in node:
                node["color"] = colors[i % len(colors)]

        self.active_visualizations[viz_id] = network_data
        await self._send_update(viz_id, network_data)

        futuristic_logger.info(
            f"[NETWORK] Created network graph '{config.title}' with {len(nodes)} nodes, {len(edges)} edges"
        )
        return network_data

    async def create_heatmap(
        self,
        matrix_data: List[List[float]],
        row_labels: List[str],
        col_labels: List[str],
        config: VisualizationConfig,
        viz_id: Optional[str] = None,
    ) -> Dict:
        """Create an interactive heatmap"""

        if not viz_id:
            viz_id = f"heatmap_{len(self.active_visualizations)}"

        # Prepare heatmap data
        heatmap_data = {
            "type": "heatmap",
            "id": viz_id,
            "config": config.dict(),
            "matrix": matrix_data,
            "row_labels": row_labels,
            "col_labels": col_labels,
            "color_scale": "viridis",  # Can be viridis, plasma, blues, reds
            "timestamp": datetime.utcnow().isoformat(),
        }

        self.active_visualizations[viz_id] = heatmap_data
        await self._send_update(viz_id, heatmap_data)

        futuristic_logger.info(
            f"[HEATMAP] Created heatmap '{config.title}' ({len(row_labels)}x{len(col_labels)})"
        )
        return heatmap_data

    async def create_volcano_plot(
        self,
        fold_changes: List[float],
        p_values: List[float],
        gene_names: List[str],
        config: VisualizationConfig,
        viz_id: Optional[str] = None,
    ) -> Dict:
        """Create a volcano plot for omics data"""

        if not viz_id:
            viz_id = f"volcano_{len(self.active_visualizations)}"

        # Calculate -log10(p-values) and prepare data
        import math

        data_points = []

        for i, (fc, pval, gene) in enumerate(
            zip(fold_changes, p_values, gene_names)
        ):
            # Avoid log(0) by using a small minimum value
            log_pval = -math.log10(max(pval, 1e-300))

            # Determine significance and color
            significant = abs(fc) > 1 and pval < 0.05
            highly_significant = abs(fc) > 2 and pval < 0.01

            color = (
                "#FF6B6B"
                if highly_significant
                else "#FFA500"
                if significant
                else "#CCCCCC"
            )

            data_points.append(
                {
                    "x": fc,
                    "y": log_pval,
                    "label": gene,
                    "color": color,
                    "significant": significant,
                    "highly_significant": highly_significant,
                }
            )

        volcano_data = {
            "type": "volcano",
            "id": viz_id,
            "config": config.dict(),
            "data": data_points,
            "thresholds": {
                "fold_change": 1.0,
                "p_value": 0.05,
                "high_fold_change": 2.0,
                "high_p_value": 0.01,
            },
            "timestamp": datetime.utcnow().isoformat(),
        }

        self.active_visualizations[viz_id] = volcano_data
        await self._send_update(viz_id, volcano_data)

        futuristic_logger.info(
            f"[VOLCANO] Created volcano plot '{config.title}' with {len(data_points)} genes"
        )
        return volcano_data

    async def create_timeline(
        self,
        events: List[Dict],
        config: VisualizationConfig,
        viz_id: Optional[str] = None,
    ) -> Dict:
        """Create an interactive timeline visualization"""

        if not viz_id:
            viz_id = f"timeline_{len(self.active_visualizations)}"

        # Sort events by date
        sorted_events = sorted(events, key=lambda x: x.get("date", ""))

        timeline_data = {
            "type": "timeline",
            "id": viz_id,
            "config": config.dict(),
            "events": sorted_events,
            "timestamp": datetime.utcnow().isoformat(),
        }

        self.active_visualizations[viz_id] = timeline_data
        await self._send_update(viz_id, timeline_data)

        futuristic_logger.info(
            f"[CALENDAR] Created timeline '{config.title}' with {len(events)} events"
        )
        return timeline_data

    def get_visualization(self, viz_id: str) -> Optional[Dict]:
        """Get visualization by ID"""
        return self.active_visualizations.get(viz_id)

    def list_visualizations(self) -> Dict:
        """List all active visualizations"""
        return {
            "count": len(self.active_visualizations),
            "visualizations": [
                {
                    "id": viz_id,
                    "type": viz_data.get("type"),
                    "title": viz_data.get("config", {}).get(
                        "title", "Untitled"
                    ),
                    "created": viz_data.get("timestamp"),
                }
                for viz_id, viz_data in self.active_visualizations.items()
            ],
        }

    async def update_visualization(self, viz_id: str, new_data: Dict) -> bool:
        """Update an existing visualization with new data"""
        if viz_id not in self.active_visualizations:
            return False

        # Update the visualization data
        self.active_visualizations[viz_id].update(new_data)
        self.active_visualizations[viz_id][
            "timestamp"
        ] = datetime.utcnow().isoformat()

        await self._send_update(viz_id, self.active_visualizations[viz_id])
        futuristic_logger.info(f"[REFRESH] Updated visualization {viz_id}")
        return True

    def remove_visualization(self, viz_id: str) -> bool:
        """Remove a visualization"""
        if viz_id in self.active_visualizations:
            del self.active_visualizations[viz_id]
            futuristic_logger.info(f"[DELETE] Removed visualization {viz_id}")
            return True
        return False

    def generate_demo_data(
        self, viz_type: VisualizationType, count: int = 50
    ) -> Dict:
        """Generate demo data for different visualization types"""
        import math
        import random

        if viz_type == VisualizationType.SCATTER_PLOT:
            return {
                "data": [
                    DataPoint(
                        x=random.uniform(0, 100),
                        y=random.uniform(0, 100),
                        label=f"Point {i}",
                        size=random.uniform(5, 15),
                    ).dict()
                    for i in range(count)
                ]
            }

        elif viz_type == VisualizationType.VOLCANO_PLOT:
            return {
                "fold_changes": [random.uniform(-5, 5) for _ in range(count)],
                "p_values": [random.uniform(0.001, 0.1) for _ in range(count)],
                "gene_names": [f"Gene_{i}" for i in range(count)],
            }

        elif viz_type == VisualizationType.NETWORK_GRAPH:
            nodes = [
                {
                    "id": f"node_{i}",
                    "label": f"Node {i}",
                    "group": random.randint(1, 3),
                }
                for i in range(count // 5)
            ]
            edges = []
            for _ in range(count // 3):
                source = random.choice(nodes)["id"]
                target = random.choice(nodes)["id"]
                if source != target:
                    edges.append(
                        {
                            "source": source,
                            "target": target,
                            "weight": random.uniform(0.1, 1.0),
                        }
                    )

            return {"nodes": nodes, "edges": edges}

        elif viz_type == VisualizationType.HEATMAP:
            matrix = [
                [random.uniform(-2, 2) for _ in range(10)] for _ in range(15)
            ]
            return {
                "matrix_data": matrix,
                "row_labels": [f"Gene_{i}" for i in range(15)],
                "col_labels": [f"Sample_{i}" for i in range(10)],
            }

        return {"message": f"Demo data for {viz_type} not implemented yet"}


# Global visualization service instance
visualization_service = EnhancedVisualizationService()
