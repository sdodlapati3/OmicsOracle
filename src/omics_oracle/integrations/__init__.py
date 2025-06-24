"""
Third-party integrations for OmicsOracle.

This module provides integrations with external services and platforms
to extend OmicsOracle's research capabilities.
"""

from .citation_managers import CitationManagerIntegration
from .pubmed import PubMedIntegration
from .service import IntegrationService

__all__ = [
    "PubMedIntegration",
    "CitationManagerIntegration",
    "IntegrationService",
]
