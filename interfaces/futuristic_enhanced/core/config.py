"""
Configuration module for enhanced interface
"""

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class EnhancedConfig:
    """Configuration for the enhanced interface"""

    # Server settings
    host: str = "0.0.0.0"
    port: int = 8001
    reload: bool = False
    log_level: str = "info"

    # Application settings
    title: str = "OmicsOracle Enhanced Interface"
    description: str = "Next-generation interface with modular architecture"
    version: str = "2.0.0-enhanced"

    # CORS settings
    cors_origins: List[str] = None
    cors_credentials: bool = True
    cors_methods: List[str] = None
    cors_headers: List[str] = None

    # WebSocket settings
    websocket_heartbeat_interval: int = 30
    max_connections: int = 100

    # Agent settings
    agent_timeout: int = 30
    max_search_results: int = 10

    def __post_init__(self):
        """Set default values for mutable fields"""
        if self.cors_origins is None:
            self.cors_origins = ["*"]
        if self.cors_methods is None:
            self.cors_methods = ["*"]
        if self.cors_headers is None:
            self.cors_headers = ["*"]


# Agent configuration
AGENT_CONFIG = {
    "search_agent": {
        "name": "Search Agent",
        "status": "active",
        "capabilities": [
            "PubMed search",
            "GEO dataset discovery",
            "Literature analysis",
        ],
        "timeout": 30,
    },
    "analysis_agent": {
        "name": "Analysis Agent",
        "status": "active",
        "capabilities": [
            "Statistical analysis",
            "Pathway enrichment",
            "Data validation",
        ],
        "timeout": 60,
    },
    "viz_agent": {
        "name": "Visualization Agent",
        "status": "active",
        "capabilities": ["Interactive plots", "Heatmaps", "Network graphs"],
        "timeout": 45,
    },
}

# UI Theme configuration
UI_THEME = {
    "primary_gradient": "linear-gradient(135deg, #1e3c72 0%, #2a5298 100%)",
    "card_background": "rgba(255,255,255,0.1)",
    "accent_color": "#4ECDC4",
    "success_color": "#4CAF50",
    "warning_color": "#FF9800",
    "error_color": "#F44336",
}
