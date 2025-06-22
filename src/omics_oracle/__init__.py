"""
OmicsOracle - AI-Powered Genomics Data Summary Agent

A comprehensive toolkit for processing, analyzing, and summarizing
genomics and omics data with AI-powered insights.
"""

__version__ = "0.1.0"
__author__ = "OmicsOracle Team"
__email__ = "team@omicsoracle.ai"
__description__ = "AI-Powered Genomics Data Summary Agent"

from .config import settings
from .core.exceptions import OmicsOracleException

__all__ = [
    "__version__",
    "__author__",
    "__email__",
    "__description__",
    "settings",
    "OmicsOracleException",
]
