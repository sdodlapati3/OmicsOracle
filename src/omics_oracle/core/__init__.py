"""
Core module for OmicsOracle.

This module provides the foundational components for the OmicsOracle application:
- Configuration management
- Exception handling
- Data models and types
- Logging infrastructure
"""

from .config import (
    Config,
    ConfigManager,
    Environment,
    load_config,
    get_config,
    is_development,
    is_production,
)

from .exceptions import (
    OmicsOracleException,
    ConfigurationError,
    ValidationError,
    GEOClientError,
    NCBIAPIError,
    GEOParseError,
    SRAError,
    NLPProcessingError,
    ModelLoadError,
    TextProcessingError,
    DatabaseError,
    DatabaseConnectionError,
    QueryError,
    MigrationError,
    APIError,
    AuthenticationError,
    AuthorizationError,
    RateLimitError,
    CLIError,
    CommandError,
    ArgumentError,
)

from .models import (
    AssayType,
    Organism,
    Platform,
    GEOSample,
    GEOSeries,
    SearchRequest,
    SearchFilters,
    GEOSeriesResponse,
    SearchResult,
    ErrorResponse,
    HealthResponse,
    MetadataExtract,
    NLPProcessingResult,
)

from .logging import setup_logging, get_logger

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
