"""
Core module for OmicsOracle.

This module provides the foundational components for OmicsOracle:
- Configuration management
- Exception handling
- Data models and types
- Logging infrastructure
"""

from .config import (
    Config,
    ConfigManager,
    Environment,
    get_config,
    is_development,
    is_production,
    load_config,
)
from .exceptions import (
    APIError,
    ArgumentError,
    AuthenticationError,
    AuthorizationError,
    CLIError,
    CommandError,
    ConfigurationError,
    DatabaseConnectionError,
    DatabaseError,
    GEOClientError,
    GEOParseError,
    MigrationError,
    ModelLoadError,
    NCBIAPIError,
    NLPProcessingError,
    OmicsOracleException,
    QueryError,
    RateLimitError,
    SRAError,
    TextProcessingError,
    ValidationError,
)
from .logging import get_logger, setup_logging
from .models import (
    AssayType,
    ErrorResponse,
    GEOSample,
    GEOSeries,
    GEOSeriesResponse,
    HealthResponse,
    MetadataExtract,
    NLPProcessingResult,
    Organism,
    Platform,
    SearchFilters,
    SearchRequest,
    SearchResult,
)

__all__ = [
    # Configuration
    "Config",
    "ConfigManager",
    "Environment",
    "load_config",
    "get_config",
    "is_development",
    "is_production",
    # Exceptions
    "OmicsOracleException",
    "ConfigurationError",
    "ValidationError",
    "GEOClientError",
    "NCBIAPIError",
    "GEOParseError",
    "SRAError",
    "NLPProcessingError",
    "ModelLoadError",
    "TextProcessingError",
    "DatabaseError",
    "DatabaseConnectionError",
    "QueryError",
    "MigrationError",
    "APIError",
    "AuthenticationError",
    "AuthorizationError",
    "RateLimitError",
    "CLIError",
    "CommandError",
    "ArgumentError",
    # Models
    "AssayType",
    "Organism",
    "Platform",
    "GEOSample",
    "GEOSeries",
    "SearchRequest",
    "SearchFilters",
    "GEOSeriesResponse",
    "SearchResult",
    "ErrorResponse",
    "HealthResponse",
    "MetadataExtract",
    "NLPProcessingResult",
    # Logging
    "setup_logging",
    "get_logger",
]

# Version information
__version__ = "1.0.0"
__author__ = "OmicsOracle Development Team"
__email__ = "dev@omicsoracle.com"
