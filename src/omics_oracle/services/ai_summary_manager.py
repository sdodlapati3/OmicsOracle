"""
Centralized AI Summary Manager for OmicsOracle.

This module consolidates all AI summary generation functionality into a single,
unified service that handles ONLY real AI summaries with honest error handling.

CRITICAL: This manager NEVER generates fake/mock summaries. It either returns
real AI-generated content or honest error messages.
"""

import logging
from typing import Any, Dict, Optional

from ..core.config import Config
from .summarizer import SummarizationService

logger = logging.getLogger(__name__)


class AISummaryManager:
    """
    Centralized manager for all AI summary generation.

    This replaces all redundant AI summary functions throughout the codebase
    with a single, honest interface that NEVER generates fake content.

    PRINCIPLES:
    1. Real AI summaries when service is available
    2. Honest error messages when service is unavailable
    3. NEVER generate fake/mock summaries
    4. Fail safely without breaking the application
    """

    _instance = None  # Singleton pattern

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self.config = Config()
        self.summarization_service = SummarizationService(self.config)
        self._initialized = True

        logger.info("AI Summary Manager initialized with honest-only policy")

    def generate_ai_summary(
        self, query: str, metadata: Dict[str, Any], geo_id: str, summary_type: str = "brief"
    ) -> Optional[str]:
        """
        Generate REAL AI summary for a dataset.

        This is the single entry point for all AI summary generation.
        Returns ONLY real AI summaries or None if unavailable.

        Args:
            query: The search query for context
            metadata: Dataset metadata
            geo_id: GEO dataset ID
            summary_type: Type of summary ('brief', 'comprehensive', 'technical')

        Returns:
            Real AI-generated summary string OR None if AI service unavailable
        """
        # Check if AI service is available first
        if not self.is_ai_service_available():
            logger.warning(f"AI service unavailable for {geo_id} - returning None")
            return None

        try:
            # Use real AI summarization service
            summary_result = self.summarization_service.summarize_dataset(
                metadata=metadata,
                query_context=query,
                summary_type=summary_type,
                dataset_id=geo_id,  # Pass the geo_id for proper cache key generation
            )

            # Extract the appropriate summary based on type
            if isinstance(summary_result, dict):
                if summary_type == "brief":
                    ai_summary = summary_result.get("brief") or summary_result.get("overview") or None
                elif summary_type == "comprehensive":
                    ai_summary = summary_result.get("overview")
                else:
                    ai_summary = summary_result.get("overview")

                if ai_summary and ai_summary.strip():
                    # Limit to ~400 words for display
                    words = ai_summary.split()
                    if len(words) > 400:
                        ai_summary = " ".join(words[:400]) + "..."

                    logger.info(f"Generated real AI summary for {geo_id}")
                    return ai_summary

            # If no valid summary from AI service, return None (honest failure)
            logger.warning(f"AI service returned empty/invalid content for {geo_id}")
            return None

        except Exception as e:
            logger.error(f"Real AI summarization failed for {geo_id}: {e}")
            return None

    def is_ai_service_available(self) -> bool:
        """Check if real AI service is available."""
        return hasattr(self.summarization_service, "client") and self.summarization_service.client is not None

    def get_summary_service_status(self) -> Dict[str, Any]:
        """Get status information about the AI summary service."""
        return {
            "ai_service_available": self.is_ai_service_available(),
            "service_type": "OpenAI GPT-4o-mini" if self.is_ai_service_available() else "Unavailable",
            "initialized": self._initialized,
            "policy": "Real AI summaries only - no fake content",
        }

    def get_error_message(self, context: str = "AI summary") -> str:
        """
        Get honest error message when AI service is unavailable.

        This provides clear, honest feedback to users about AI service status.
        """
        if not self.is_ai_service_available():
            return f"{context} unavailable (OpenAI service not configured)"
        else:
            return f"{context} temporarily unavailable (service error)"


# Global singleton instance
ai_summary_manager = AISummaryManager()
