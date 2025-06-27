"""
Domain exceptions for OmicsOracle.

This module defines all custom exceptions used throughout the domain layer,
providing clear error types and messages for different failure scenarios.
"""

from typing import Any, Dict, List, Optional


class DomainError(Exception):
    """Base exception for all domain-related errors."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} (Details: {self.details})"
        return self.message


class ValidationError(DomainError):
    """Raised when domain object validation fails."""

    def __init__(
        self,
        message: str,
        field: Optional[str] = None,
        value: Optional[Any] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, details)
        self.field = field
        self.value = value


class SearchError(DomainError):
    """Raised when search operations fail."""

    def __init__(
        self,
        message: str,
        query: Optional[str] = None,
        source: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, details)
        self.query = query
        self.source = source


class RepositoryError(DomainError):
    """Raised when repository operations fail."""

    def __init__(
        self,
        message: str,
        operation: Optional[str] = None,
        resource: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, details)
        self.operation = operation
        self.resource = resource


class DatasetNotFoundError(RepositoryError):
    """Raised when a requested dataset cannot be found."""

    def __init__(self, geo_id: str, details: Optional[Dict[str, Any]] = None):
        message = f"Dataset with GEO ID '{geo_id}' not found"
        super().__init__(
            message, operation="get", resource=geo_id, details=details
        )
        self.geo_id = geo_id


class InvalidGeoIdError(ValidationError):
    """Raised when an invalid GEO ID is provided."""

    def __init__(self, geo_id: str, details: Optional[Dict[str, Any]] = None):
        message = f"Invalid GEO ID format: '{geo_id}'"
        super().__init__(message, field="geo_id", value=geo_id, details=details)
        self.geo_id = geo_id


class SearchTimeoutError(SearchError):
    """Raised when search operations timeout."""

    def __init__(
        self,
        query: str,
        timeout_seconds: float,
        details: Optional[Dict[str, Any]] = None,
    ):
        message = f"Search timed out after {timeout_seconds} seconds"
        super().__init__(message, query=query, details=details)
        self.timeout_seconds = timeout_seconds


class ExternalServiceError(DomainError):
    """Raised when external service calls fail."""

    def __init__(
        self,
        service: str,
        message: str,
        status_code: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(f"{service} service error: {message}", details)
        self.service = service
        self.status_code = status_code


class InfrastructureError(DomainError):
    """Raised when infrastructure or external service operations fail."""

    def __init__(
        self,
        message: str,
        service: Optional[str] = None,
        operation: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message, details)
        self.service = service
        self.operation = operation


class ConfigurationError(DomainError):
    """Raised when configuration is invalid or missing."""

    def __init__(
        self,
        setting: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            f"Configuration error for '{setting}': {message}", details
        )
        self.setting = setting


class BusinessRuleViolationError(DomainError):
    """Raised when business rules are violated."""

    def __init__(
        self, rule: str, message: str, details: Optional[Dict[str, Any]] = None
    ):
        super().__init__(
            f"Business rule violation '{rule}': {message}", details
        )
        self.rule = rule


class ConcurrencyError(DomainError):
    """Raised when concurrent access conflicts occur."""

    def __init__(
        self,
        resource: str,
        message: str = "Resource is being modified by another process",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            f"Concurrency error for '{resource}': {message}", details
        )
        self.resource = resource


class RateLimitExceededError(DomainError):
    """Raised when rate limits are exceeded."""

    def __init__(
        self,
        limit: int,
        window_seconds: int,
        current_count: int,
        details: Optional[Dict[str, Any]] = None,
    ):
        message = f"Rate limit exceeded: {current_count}/{limit} requests in {window_seconds}s"
        super().__init__(message, details)
        self.limit = limit
        self.window_seconds = window_seconds
        self.current_count = current_count


class InsufficientPermissionsError(DomainError):
    """Raised when user lacks required permissions."""

    def __init__(
        self,
        operation: str,
        resource: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        message = f"Insufficient permissions for operation '{operation}'"
        if resource:
            message += f" on resource '{resource}'"
        super().__init__(message, details)
        self.operation = operation
        self.resource = resource


class DataIntegrityError(DomainError):
    """Raised when data integrity constraints are violated."""

    def __init__(
        self,
        constraint: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            f"Data integrity error '{constraint}': {message}", details
        )
        self.constraint = constraint


class NetworkError(ExternalServiceError):
    """Raised when network-related errors occur."""

    def __init__(
        self,
        operation: str,
        url: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            "Network",
            f"{operation} failed for {url}: {message}",
            details=details,
        )
        self.operation = operation
        self.url = url


class ParseError(DomainError):
    """Raised when data parsing fails."""

    def __init__(
        self,
        data_type: str,
        message: str,
        data_sample: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(f"Failed to parse {data_type}: {message}", details)
        self.data_type = data_type
        self.data_sample = data_sample


class QuotaExceededError(DomainError):
    """Raised when resource quotas are exceeded."""

    def __init__(
        self,
        resource: str,
        quota: int,
        current_usage: int,
        details: Optional[Dict[str, Any]] = None,
    ):
        message = f"Quota exceeded for {resource}: {current_usage}/{quota}"
        super().__init__(message, details)
        self.resource = resource
        self.quota = quota
        self.current_usage = current_usage


class ServiceUnavailableError(ExternalServiceError):
    """Raised when external services are unavailable."""

    def __init__(
        self,
        service: str,
        retry_after: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        message = "Service temporarily unavailable"
        if retry_after:
            message += f", retry after {retry_after} seconds"
        super().__init__(service, message, status_code=503, details=details)
        self.retry_after = retry_after


# Exception groups for easier handling
VALIDATION_EXCEPTIONS = (ValidationError, InvalidGeoIdError)
SEARCH_EXCEPTIONS = (SearchError, SearchTimeoutError)
REPOSITORY_EXCEPTIONS = (RepositoryError, DatasetNotFoundError)
EXTERNAL_SERVICE_EXCEPTIONS = (
    ExternalServiceError,
    NetworkError,
    ServiceUnavailableError,
)
SECURITY_EXCEPTIONS = (InsufficientPermissionsError, RateLimitExceededError)
DATA_EXCEPTIONS = (DataIntegrityError, ParseError)
RESOURCE_EXCEPTIONS = (QuotaExceededError, ConcurrencyError)


def is_retryable_error(exception: Exception) -> bool:
    """
    Determine if an exception represents a retryable error.

    Args:
        exception: The exception to check

    Returns:
        True if the operation can be retried, False otherwise
    """
    retryable_types = (
        SearchTimeoutError,
        NetworkError,
        ServiceUnavailableError,
        ConcurrencyError,
    )

    return isinstance(exception, retryable_types)


def get_error_code(exception: Exception) -> str:
    """
    Get a standardized error code for an exception.

    Args:
        exception: The exception to get code for

    Returns:
        Standardized error code string
    """
    error_codes = {
        ValidationError: "VALIDATION_ERROR",
        InvalidGeoIdError: "INVALID_GEO_ID",
        SearchError: "SEARCH_ERROR",
        SearchTimeoutError: "SEARCH_TIMEOUT",
        RepositoryError: "REPOSITORY_ERROR",
        DatasetNotFoundError: "DATASET_NOT_FOUND",
        ExternalServiceError: "EXTERNAL_SERVICE_ERROR",
        NetworkError: "NETWORK_ERROR",
        ServiceUnavailableError: "SERVICE_UNAVAILABLE",
        ConfigurationError: "CONFIGURATION_ERROR",
        BusinessRuleViolationError: "BUSINESS_RULE_VIOLATION",
        ConcurrencyError: "CONCURRENCY_ERROR",
        RateLimitExceededError: "RATE_LIMIT_EXCEEDED",
        InsufficientPermissionsError: "INSUFFICIENT_PERMISSIONS",
        DataIntegrityError: "DATA_INTEGRITY_ERROR",
        ParseError: "PARSE_ERROR",
        QuotaExceededError: "QUOTA_EXCEEDED",
    }

    return error_codes.get(type(exception), "UNKNOWN_ERROR")


def create_error_details(exception: Exception) -> Dict[str, Any]:
    """
    Create standardized error details dictionary from an exception.

    Args:
        exception: The exception to extract details from

    Returns:
        Dictionary containing error details
    """
    details = {
        "error_code": get_error_code(exception),
        "error_message": str(exception),
        "error_type": type(exception).__name__,
        "is_retryable": is_retryable_error(exception),
    }

    # Add specific exception attributes
    if isinstance(exception, DomainError):
        details.update(exception.details)

    if hasattr(exception, "field"):
        details["field"] = exception.field

    if hasattr(exception, "value"):
        details["value"] = str(exception.value)

    if hasattr(exception, "query"):
        details["query"] = exception.query

    if hasattr(exception, "source"):
        details["source"] = exception.source

    if hasattr(exception, "geo_id"):
        details["geo_id"] = exception.geo_id

    if hasattr(exception, "service"):
        details["service"] = exception.service

    if hasattr(exception, "status_code"):
        details["status_code"] = exception.status_code

    return details
