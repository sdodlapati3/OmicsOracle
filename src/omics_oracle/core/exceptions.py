"""
Custom exceptions for OmicsOracle.

This module defines the exception hierarchy used throughout the application.
All custom exceptions inherit from OmicsOracleException for consistent
error handling and logging.
"""

from typing import Optional, Dict, Any


class OmicsOracleException(Exception):
    """Base exception for all OmicsOracle errors."""
    
    def __init__(
        self, 
        message: str, 
        code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Initialize exception.
        
        Args:
            message: Error message
            code: Error code for API responses
            details: Additional error details
        """
        super().__init__(message)
        self.message = message
        self.code = code or self.__class__.__name__.upper()
        self.details = details or {}


class ConfigurationError(OmicsOracleException):
    """Raised when there are configuration-related errors."""


class ValidationError(OmicsOracleException):
    """Raised when input validation fails."""


class GEOClientError(OmicsOracleException):
    """Raised when GEO/NCBI client operations fail."""


class NCBIAPIError(GEOClientError):
    """Raised when NCBI API requests fail."""


class GEOParseError(GEOClientError):
    """Raised when GEO data parsing fails."""


class SRAError(GEOClientError):
    """Raised when SRA operations fail."""


class NLPProcessingError(OmicsOracleException):
    """Raised when NLP processing operations fail."""


class ModelLoadError(NLPProcessingError):
    """Raised when NLP model loading fails."""


class TextProcessingError(NLPProcessingError):
    """Raised when text processing fails."""


class DatabaseError(OmicsOracleException):
    """Raised when database operations fail."""


class DatabaseConnectionError(DatabaseError):
    """Raised when database connection fails."""


class QueryError(DatabaseError):
    """Raised when database queries fail."""


class MigrationError(DatabaseError):
    """Raised when database migrations fail."""


class APIError(OmicsOracleException):
    """Raised when API operations fail."""


class AuthenticationError(APIError):
    """Raised when authentication fails."""


class AuthorizationError(APIError):
    """Raised when authorization fails."""


class RateLimitError(APIError):
    """Raised when rate limits are exceeded."""


class CLIError(OmicsOracleException):
    """Raised when CLI operations fail."""


class CommandError(CLIError):
    """Raised when CLI commands fail."""


class ArgumentError(CLIError):
    """Raised when CLI arguments are invalid."""


# Legacy aliases for backward compatibility
DataProcessingError = NLPProcessingError
GEOAPIError = GEOClientError
AIServiceError = NLPProcessingError
FileProcessingError = ValidationError
