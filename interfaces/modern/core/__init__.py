"""
OmicsOracle Modern Web Interface Core Module
Provides configuration, logging, and application factory patterns
"""

from .app_factory import create_app
from .config import Config, DevelopmentConfig, ProductionConfig, TestingConfig
from .exceptions import (
    OmicsOracleException,
    SearchException,
    ValidationException,
)
from .logging_config import setup_logging

__all__ = [
    "Config",
    "DevelopmentConfig",
    "ProductionConfig",
    "TestingConfig",
    "create_app",
    "setup_logging",
    "OmicsOracleException",
    "SearchException",
    "ValidationException",
]
