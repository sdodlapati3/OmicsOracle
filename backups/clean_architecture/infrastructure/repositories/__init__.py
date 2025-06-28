"""
Infrastructure layer repository implementations.

This module contains concrete implementations of domain repositories
using external data sources and APIs.
"""

from .geo_search_repository import GEOSearchRepository

__all__ = ["GEOSearchRepository"]
