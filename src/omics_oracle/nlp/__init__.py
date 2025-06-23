"""
Natural Language Processing module for OmicsOracle.

Provides NLP capabilities for genomics data analysis.
"""

from .biomedical_ner import BiomedicalNER, EnhancedBiologicalSynonymMapper
from .prompt_interpreter import BiologicalSynonymMapper, PromptInterpreter

__all__ = [
    "PromptInterpreter",
    "BiologicalSynonymMapper",
    "BiomedicalNER",
    "EnhancedBiologicalSynonymMapper",
]
