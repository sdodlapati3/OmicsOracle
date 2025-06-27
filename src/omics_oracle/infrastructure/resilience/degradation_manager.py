"""
Degradation Manager

Provides graceful degradation strategies:
- Feature flagging
- Circuit breaker integration
- Fallback mechanisms
- Performance-based degradation
"""

import logging
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger(__name__)


class DegradationStrategy(Enum):
    """Degradation strategy enumeration."""

    DISABLE_FEATURE = "disable_feature"
    FALLBACK_VALUE = "fallback_value"
    CACHED_RESPONSE = "cached_response"
    SIMPLIFIED_RESPONSE = "simplified_response"


class DegradationRule(ABC):
    """Abstract base class for degradation rules."""

    @abstractmethod
    def should_degrade(self, context: Dict[str, Any]) -> bool:
        """Determine if service should degrade."""
        pass


class DegradationManager:
    """Graceful degradation management system."""

    def __init__(self):
        self._rules: Dict[str, DegradationRule] = {}
        self._fallbacks: Dict[str, Callable] = {}

    def register_rule(self, service_name: str, rule: DegradationRule) -> None:
        """Register degradation rule for service."""
        self._rules[service_name] = rule

    def register_fallback(self, service_name: str, fallback: Callable) -> None:
        """Register fallback function for service."""
        self._fallbacks[service_name] = fallback

    def should_degrade(
        self, service_name: str, context: Dict[str, Any]
    ) -> bool:
        """Check if service should degrade."""
        if service_name in self._rules:
            return self._rules[service_name].should_degrade(context)
        return False

    def get_fallback_response(self, service_name: str, *args, **kwargs) -> Any:
        """Get fallback response for service."""
        if service_name in self._fallbacks:
            return self._fallbacks[service_name](*args, **kwargs)
        return None
