"""
API blueprints for OmicsOracle modern interface
Provides REST endpoints for web interface
"""

from .enhanced_api import enhanced_bp
from .export_api import export_bp
from .health_api import health_bp
from .main_routes import main_bp
from .search_api import search_bp

__all__ = ["search_bp", "health_bp", "export_bp", "main_bp", "enhanced_bp"]
