"""
OmicsOracle GEO Tools Integration Module

This module provides unified interfaces to all GEO-related libraries:
- entrezpy: NCBI E-utilities access
- GEOparse: GEO SOFT file parsing
- pysradb: SRA metadata retrieval
- GEOfetch: Standardized data download
- GEOmetadb: SQLite GEO database
"""

from .geo_client import UnifiedGEOClient

__version__ = "0.1.0"
__all__ = ["UnifiedGEOClient"]
