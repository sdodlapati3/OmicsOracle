"""
Custom exceptions for OmicsOracle modern interface
"""

from typing import Any, Dict, Optional


class OmicsOracleException(Exception):
    """Base exception for OmicsOracle application"""

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for API responses"""
        return {
            "error": self.__class__.__name__,
            "message": self.message,
            "error_code": self.error_code,
            "details": self.details,
        }


class ValidationException(OmicsOracleException):
    """Raised when input validation fails"""

    pass


class SearchException(OmicsOracleException):
    """Raised when search operations fail"""

    pass


class DatabaseException(OmicsOracleException):
    """Raised when database operations fail"""

    pass


class ConfigurationException(OmicsOracleException):
    """Raised when configuration is invalid"""

    pass


class CacheException(OmicsOracleException):
    """Raised when cache operations fail"""

    pass


class ExportException(OmicsOracleException):
    """Raised when export operations fail"""

    pass


class RateLimitException(OmicsOracleException):
    """Raised when rate limits are exceeded"""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: Optional[int] = None,
        **kwargs,
    ):
        super().__init__(message, **kwargs)
        self.retry_after = retry_after

    def to_dict(self) -> Dict[str, Any]:
        result = super().to_dict()
        if self.retry_after:
            result["retry_after"] = self.retry_after
        return result
