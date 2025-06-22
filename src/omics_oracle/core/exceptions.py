"""
Core exceptions for OmicsOracle application.
"""


class OmicsOracleException(Exception):
    """Base exception for OmicsOracle application."""
    
    def __init__(self, message: str, error_code: str = None):
        self.message = message
        self.error_code = error_code
        super().__init__(self.message)


class ConfigurationError(OmicsOracleException):
    """Raised when there's a configuration error."""
    pass


class DataProcessingError(OmicsOracleException):
    """Raised when there's an error processing data."""
    pass


class GEOAPIError(OmicsOracleException):
    """Raised when there's an error with GEO API calls."""
    pass


class DatabaseError(OmicsOracleException):
    """Raised when there's a database operation error."""
    pass


class AIServiceError(OmicsOracleException):
    """Raised when there's an error with AI services."""
    pass


class ValidationError(OmicsOracleException):
    """Raised when data validation fails."""
    pass


class AuthenticationError(OmicsOracleException):
    """Raised when authentication fails."""
    pass


class AuthorizationError(OmicsOracleException):
    """Raised when authorization fails."""
    pass


class RateLimitError(OmicsOracleException):
    """Raised when rate limit is exceeded."""
    pass


class FileProcessingError(OmicsOracleException):
    """Raised when file processing fails."""
    pass
